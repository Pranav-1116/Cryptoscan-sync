"""Optional live GCP scan. Requires google-cloud-kms / storage; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.common.finding import cloud_finding


def scan_gcp(*, project: str | None = None) -> list[dict[str, Any]]:
    project_id = project or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if not project_id:
        return []
    findings: list[dict[str, Any]] = []
    try:
        from google.cloud import kms  # type: ignore

        client = kms.KeyManagementServiceClient()
        parent = f"projects/{project_id}/locations/global"
        for key in list(client.list_crypto_keys(request={"parent": parent}))[:40]:
            findings.append(
                cloud_finding(
                    source_type="GCP_KMS_KEY",
                    resource=key.name,
                    algorithm="AES-256",
                    purpose="KEY_MANAGEMENT",
                    file_path=f"gcp://kms/{key.name}",
                    provider="GCP",
                    extra={"scan_method": "LIVE_API"},
                )
            )
    except Exception:
        pass
    try:
        from google.cloud import storage  # type: ignore

        client = storage.Client(project=project_id)
        for bucket in list(client.list_buckets())[:40]:
            enc = bool(getattr(bucket, "default_kms_key_name", None) or getattr(bucket, "encryption", None))
            findings.append(
                cloud_finding(
                    source_type="GCP_STORAGE_BUCKET",
                    resource=bucket.name,
                    algorithm="AES-256",
                    purpose="DATA_AT_REST_ENCRYPTION",
                    file_path=f"gcp://storage/{bucket.name}",
                    provider="GCP",
                    issue=None if enc else None,
                    extra={"scan_method": "LIVE_API", "default_kms": getattr(bucket, "default_kms_key_name", None)},
                )
            )
    except Exception:
        pass
    return findings
