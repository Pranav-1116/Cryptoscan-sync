"""Parse Terraform HCL-ish files for KMS, S3, RDS, and listener crypto."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cloud_scanner.common.finding import cloud_finding

RESOURCE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)

KMS_SPEC = re.compile(r'customer_master_key_spec\s*=\s*"([^"]+)"')
SSE = re.compile(r'sse_algorithm\s*=\s*"([^"]+)"')
STORAGE_ENC = re.compile(r"storage_encrypted\s*=\s*(true|false)")
SSL_POLICY = re.compile(r'ssl_policy\s*=\s*"([^"]+)"')
ROTATION = re.compile(r"enable_key_rotation\s*=\s*(true|false)")


def _line(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def _block(text: str, start: int) -> str:
    depth = 0
    for idx in range(start, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    return text[start:]


def _kms_algo(spec: str | None) -> tuple[str, int | None]:
    raw = (spec or "SYMMETRIC_DEFAULT").upper()
    if "SYMMETRIC" in raw:
        return "AES-256", 256
    if raw.startswith("RSA_"):
        bits = int(raw.split("_")[1]) if raw.split("_")[1].isdigit() else None
        return "RSA", bits
    if "ECC_NIST_P256" in raw:
        return "ECDSA", 256
    if "ECC_NIST_P384" in raw:
        return "ECDSA", 384
    return raw, None


def parse_terraform(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[dict[str, Any]] = []
    for match in RESOURCE.finditer(text):
        rtype, name = match.group(1), match.group(2)
        body = _block(text, match.end() - 1)
        line = _line(text, match.start())
        resource = f"{rtype}.{name}"
        if rtype == "aws_kms_key":
            spec = KMS_SPEC.search(body)
            algo, bits = _kms_algo(spec.group(1) if spec else None)
            rotation = ROTATION.search(body)
            findings.append(
                cloud_finding(
                    source_type="AWS_KMS_KEY",
                    resource=resource,
                    algorithm=algo,
                    key_size=bits,
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    line_number=line,
                    extra={"rotation_enabled": rotation.group(1) == "true" if rotation else False},
                )
            )
        elif rtype in {"aws_s3_bucket", "aws_s3_bucket_server_side_encryption_configuration"}:
            sse = SSE.search(body)
            if rtype == "aws_s3_bucket" and "server_side_encryption" not in body and not sse:
                findings.append(
                    cloud_finding(
                        source_type="AWS_S3_BUCKET",
                        resource=resource,
                        algorithm=None,
                        purpose="DATA_AT_REST_ENCRYPTION",
                        file_path=str(path),
                        line_number=line,
                        issue="NO_ENCRYPTION",
                    )
                )
            else:
                algo = "AES-256" if not sse or sse.group(1).upper() in {"AES256", "AES-256"} else "KMS"
                findings.append(
                    cloud_finding(
                        source_type="AWS_S3_BUCKET",
                        resource=resource,
                        algorithm=algo,
                        purpose="DATA_AT_REST_ENCRYPTION",
                        file_path=str(path),
                        line_number=line,
                    )
                )
        elif rtype in {"aws_db_instance", "aws_rds_cluster"}:
            enc = STORAGE_ENC.search(body)
            encrypted = enc.group(1) == "true" if enc else False
            findings.append(
                cloud_finding(
                    source_type="AWS_RDS_INSTANCE",
                    resource=resource,
                    algorithm="AES-256-XTS" if encrypted else None,
                    purpose="DATABASE_ENCRYPTION",
                    file_path=str(path),
                    line_number=line,
                    issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                    extra={"storage_encrypted": encrypted},
                )
            )
        elif rtype in {"aws_lb_listener", "aws_alb_listener"}:
            policy = SSL_POLICY.search(body)
            name_policy = policy.group(1) if policy else "DEFAULT"
            weak = any(token in name_policy.upper() for token in ("TLS-1-0", "TLS-1-1", "SSL"))
            findings.append(
                cloud_finding(
                    source_type="AWS_ELB_LISTENER",
                    resource=resource,
                    algorithm="TLS1.0" if weak else "TLS",
                    purpose="LOAD_BALANCER_TLS",
                    file_path=str(path),
                    line_number=line,
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={"ssl_policy": name_policy},
                )
            )
        elif rtype == "azurerm_key_vault_key":
            findings.append(
                cloud_finding(
                    source_type="AZURE_KEY_VAULT_KEY",
                    resource=resource,
                    algorithm="RSA",
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    line_number=line,
                    provider="AZURE",
                )
            )
        elif rtype == "google_kms_crypto_key":
            findings.append(
                cloud_finding(
                    source_type="GCP_KMS_KEY",
                    resource=resource,
                    algorithm="AES-256",
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    line_number=line,
                    provider="GCP",
                )
            )
    return findings
