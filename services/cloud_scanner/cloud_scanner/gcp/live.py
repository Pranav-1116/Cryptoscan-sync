"""Optional live GCP scan. Requires google-cloud-*; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.gcp.scanners import (
    scan_cloud_dns,
    scan_cloud_kms,
    scan_cloud_run,
    scan_cloud_sql,
    scan_gcs,
    scan_gke,
    scan_load_balancer,
    scan_memorystore,
    scan_pubsub,
    scan_secret_manager,
)


def scan_gcp(*, project: str | None = None, telemetry=None) -> list[dict[str, Any]]:
    project_id = project or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if telemetry is not None:
        telemetry.providers_attempted.add("GCP")
    if not project_id:
        if telemetry is not None:
            telemetry.record_error("GCP", "project", "global", RuntimeError("no project id configured"))
        return []
    findings: list[dict[str, Any]] = []
    for service, call in (
        ("kms", lambda: _kms(project_id)),
        ("storage", lambda: _storage(project_id)),
        ("sql", lambda: _sql(project_id)),
        ("loadbalancer", lambda: _ssl_policies(project_id)),
        ("secretmanager", lambda: _secrets(project_id)),
        ("pubsub", lambda: _pubsub(project_id)),
        ("gke", lambda: _gke(project_id)),
        ("dns", lambda: _cloud_dns(project_id)),
        ("memorystore", lambda: _memorystore(project_id)),
        ("cloudrun", lambda: _cloud_run(project_id)),
    ):
        try:
            value = call()
            findings.extend(value)
            if telemetry is not None:
                telemetry.record_resources(len(value))
        except Exception as exc:
            if telemetry is not None:
                telemetry.record_error("GCP", service, project_id, exc)
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


def _secrets(project_id: str) -> list[dict[str, Any]]:
    try:
        from google.cloud import secretmanager  # type: ignore

        return scan_secret_manager(secretmanager.SecretManagerServiceClient(), project=project_id)
    except Exception:
        return []


def _pubsub(project_id: str) -> list[dict[str, Any]]:
    try:
        from google.cloud import pubsub_v1  # type: ignore

        return scan_pubsub(pubsub_v1.PublisherClient(), project=project_id)
    except Exception:
        return []


def _gke(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        return scan_gke(build("container", "v1", cache_discovery=False), project=project_id)
    except Exception:
        return []


def _ssl_policies(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        return scan_load_balancer(build("compute", "v1", cache_discovery=False), project=project_id)
    except Exception:
        return []


def _cloud_dns(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        return scan_cloud_dns(build("dns", "v1", cache_discovery=False), project=project_id)
    except Exception:
        return []


def _memorystore(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        return scan_memorystore(build("redis", "v1", cache_discovery=False), project=project_id)
    except Exception:
        return []


def _cloud_run(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        return scan_cloud_run(build("run", "v2", cache_discovery=False), project=project_id)
    except Exception:
        return []
