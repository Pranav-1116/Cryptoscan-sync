"""Parse CloudFormation YAML/JSON for encryption settings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from cloud_scanner.common.finding import cloud_finding


def parse_cloudformation(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    data: Any
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except Exception:
            return []
    if not isinstance(data, dict) or "Resources" not in data:
        return []
    findings: list[dict[str, Any]] = []
    for name, resource in (data.get("Resources") or {}).items():
        if not isinstance(resource, dict):
            continue
        rtype = resource.get("Type") or ""
        props = resource.get("Properties") or {}
        if rtype == "AWS::KMS::Key":
            spec = str(props.get("KeySpec") or "SYMMETRIC_DEFAULT")
            algo = "AES-256" if "SYMMETRIC" in spec.upper() else spec
            findings.append(
                cloud_finding(
                    source_type="AWS_KMS_KEY",
                    resource=name,
                    algorithm=algo,
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                )
            )
        elif rtype == "AWS::S3::Bucket":
            enc = ((props.get("BucketEncryption") or {}).get("ServerSideEncryptionConfiguration"))
            if not enc:
                findings.append(
                    cloud_finding(
                        source_type="AWS_S3_BUCKET",
                        resource=name,
                        algorithm=None,
                        purpose="DATA_AT_REST_ENCRYPTION",
                        file_path=str(path),
                        issue="NO_ENCRYPTION",
                    )
                )
            else:
                findings.append(
                    cloud_finding(
                        source_type="AWS_S3_BUCKET",
                        resource=name,
                        algorithm="AES-256",
                        purpose="DATA_AT_REST_ENCRYPTION",
                        file_path=str(path),
                    )
                )
        elif rtype in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"}:
            encrypted = bool(props.get("StorageEncrypted"))
            findings.append(
                cloud_finding(
                    source_type="AWS_RDS_INSTANCE",
                    resource=name,
                    algorithm="AES-256-XTS" if encrypted else None,
                    purpose="DATABASE_ENCRYPTION",
                    file_path=str(path),
                    issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                )
            )
    return findings
