"""Optional live GCP scan. Requires google-cloud-*; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.common.finding import cloud_finding


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

        client = kms.KeyManagementServiceClient()
        parent = f"projects/{project_id}/locations/global"
        findings = []
        for key in list(client.list_crypto_keys(request={"parent": parent}))[:40]:
            template = getattr(key, "version_template", None)
            algo_name = str(getattr(getattr(template, "algorithm", None), "name", "") or "AES-256")
            algo = "RSA" if "RSA" in algo_name.upper() else ("ECDSA" if "EC_" in algo_name.upper() else "AES-256")
            findings.append(
                cloud_finding(
                    source_type="GCP_KMS_KEY",
                    resource=key.name,
                    algorithm=algo,
                    purpose="KEY_MANAGEMENT",
                    file_path=f"gcp://kms/{key.name}",
                    provider="GCP",
                    extra={
                        "scan_method": "LIVE_API",
                        "algorithm": algo_name,
                        "protection_level": str(getattr(getattr(template, "protection_level", None), "name", "")),
                    },
                )
            )
        return findings
    except Exception:
        return []


def _storage(project_id: str) -> list[dict[str, Any]]:
    try:
        from google.cloud import storage  # type: ignore

        client = storage.Client(project=project_id)
        findings = []
        for bucket in list(client.list_buckets())[:40]:
            kms_name = getattr(bucket, "default_kms_key_name", None)
            findings.append(
                cloud_finding(
                    source_type="GCP_STORAGE_BUCKET",
                    resource=bucket.name,
                    algorithm="AES-256",
                    purpose="DATA_AT_REST_ENCRYPTION",
                    file_path=f"gcp://storage/{bucket.name}",
                    provider="GCP",
                    issue=None if kms_name else None,
                    extra={"scan_method": "LIVE_API", "default_kms": kms_name},
                )
            )
        return findings
    except Exception:
        return []


def _sql(project_id: str) -> list[dict[str, Any]]:
    try:
        from google.cloud.sql.connector import Connector  # type: ignore  # noqa: F401
    except Exception:
        pass
    try:
        from googleapiclient.discovery import build  # type: ignore

        service = build("sqladmin", "v1beta4", cache_discovery=False)
        items = ((service.instances().list(project=project_id).execute() or {}).get("items")) or []
        findings = []
        for inst in items[:30]:
            settings = inst.get("settings") or {}
            encrypted = bool(settings.get("diskEncryptionConfiguration") or True)
            findings.append(
                cloud_finding(
                    source_type="GCP_CLOUD_SQL",
                    resource=inst.get("name") or "sql",
                    algorithm="AES-256" if encrypted else None,
                    purpose="DATABASE_ENCRYPTION",
                    file_path=f"gcp://sql/{inst.get('name')}",
                    provider="GCP",
                    issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                    extra={"scan_method": "LIVE_API", "database_version": inst.get("databaseVersion")},
                )
            )
        return findings
    except Exception:
        return []


def _ssl_policies(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        service = build("compute", "v1", cache_discovery=False)
        items = ((service.sslPolicies().list(project=project_id).execute() or {}).get("items")) or []
        findings = []
        for policy in items[:30]:
            version = (policy.get("minTlsVersion") or "TLS_1_0").upper()
            weak = version in {"TLS_1_0", "TLS_1_1"}
            findings.append(
                cloud_finding(
                    source_type="GCP_SSL_POLICY",
                    resource=policy.get("name") or "ssl-policy",
                    algorithm="TLS1.0" if weak else "TLS",
                    purpose="LOAD_BALANCER_TLS",
                    file_path=f"gcp://sslpolicy/{policy.get('name')}",
                    provider="GCP",
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={"scan_method": "LIVE_API", "min_tls_version": version},
                )
            )
        return findings
    except Exception:
        return []
