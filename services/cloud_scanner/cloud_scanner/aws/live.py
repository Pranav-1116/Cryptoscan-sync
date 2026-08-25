"""Optional live AWS scan. Requires boto3 and credentials; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.common.finding import cloud_finding


def live_enabled(flag: bool | None = None) -> bool:
    if flag is not None:
        return bool(flag)
    return os.environ.get("CRYPTOSCAN_CLOUD_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def scan_aws(*, regions: list[str] | None = None) -> list[dict[str, Any]]:
    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    session = boto3.Session()
    region_list = regions or session.get_available_regions("kms") or [session.region_name or "us-east-1"]
    for region in region_list[:8]:
        try:
            kms = session.client("kms", region_name=region)
            keys = kms.list_keys().get("Keys") or []
            for item in keys[:50]:
                meta = kms.describe_key(KeyId=item["KeyId"])["KeyMetadata"]
                spec = meta.get("KeySpec") or "SYMMETRIC_DEFAULT"
                algo = "AES-256" if "SYMMETRIC" in spec else spec
                findings.append(
                    cloud_finding(
                        source_type="AWS_KMS_KEY",
                        resource=meta.get("Arn") or item["KeyId"],
                        algorithm=algo,
                        purpose="KEY_MANAGEMENT",
                        file_path=f"aws://{region}/kms/{item['KeyId']}",
                        extra={"region": region, "scan_method": "LIVE_API", "key_state": meta.get("KeyState")},
                    )
                )
        except (BotoCoreError, ClientError, Exception):
            continue
        try:
            s3 = session.client("s3", region_name=region)
            for bucket in (s3.list_buckets().get("Buckets") or [])[:50]:
                name = bucket["Name"]
                try:
                    s3.get_bucket_encryption(Bucket=name)
                    issue = None
                    algo = "AES-256"
                except ClientError as exc:
                    code = (exc.response.get("Error") or {}).get("Code")
                    if code == "ServerSideEncryptionConfigurationNotFoundError":
                        issue = "NO_ENCRYPTION"
                        algo = None
                    else:
                        continue
                findings.append(
                    cloud_finding(
                        source_type="AWS_S3_BUCKET",
                        resource=name,
                        algorithm=algo,
                        purpose="DATA_AT_REST_ENCRYPTION",
                        file_path=f"aws://s3/{name}",
                        issue=issue,
                        extra={"region": region, "scan_method": "LIVE_API"},
                    )
                )
        except (BotoCoreError, ClientError, Exception):
            continue
    return findings
