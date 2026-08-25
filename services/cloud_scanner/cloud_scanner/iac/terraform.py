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
            key_type = re.search(r'key_type\s*=\s*"([^"]+)"', body)
            key_size = re.search(r"key_size\s*=\s*(\d+)", body)
            algo = (key_type.group(1) if key_type else "RSA").upper()
            findings.append(
                cloud_finding(
                    source_type="AZURE_KEY_VAULT_KEY",
                    resource=resource,
                    algorithm=algo,
                    key_size=int(key_size.group(1)) if key_size else None,
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    line_number=line,
                    provider="AZURE",
                )
            )
        elif rtype == "azurerm_storage_account":
            https = re.search(r"https_traffic_only_enabled\s*=\s*(true|false)", body) or re.search(
                r"enable_https_traffic_only\s*=\s*(true|false)", body
            )
            encrypted = "encryption" in body or "infrastructure_encryption_enabled" in body
            https_ok = https.group(1) != "false" if https else True
            issue = None if https_ok and encrypted else ("NO_HTTPS_ONLY" if not https_ok else "NO_ENCRYPTION")
            findings.append(
                cloud_finding(
                    source_type="AZURE_STORAGE_ACCOUNT",
                    resource=resource,
                    algorithm="AES-256" if encrypted else None,
                    purpose="DATA_AT_REST_ENCRYPTION",
                    file_path=str(path),
                    line_number=line,
                    provider="AZURE",
                    issue=issue,
                )
            )
        elif rtype == "google_kms_crypto_key":
            algo_m = re.search(r'algorithm\s*=\s*"([^"]+)"', body)
            algo = (algo_m.group(1) if algo_m else "AES-256").upper()
            if "RSA" in algo:
                mapped, bits = "RSA", 2048
            else:
                mapped, bits = "AES-256", 256
            findings.append(
                cloud_finding(
                    source_type="GCP_KMS_KEY",
                    resource=resource,
                    algorithm=mapped,
                    key_size=bits,
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    line_number=line,
                    provider="GCP",
                )
            )
        elif rtype == "google_storage_bucket":
            enc = "encryption" in body or "default_kms_key_name" in body
            findings.append(
                cloud_finding(
                    source_type="GCP_STORAGE_BUCKET",
                    resource=resource,
                    algorithm="AES-256" if enc else None,
                    purpose="DATA_AT_REST_ENCRYPTION",
                    file_path=str(path),
                    line_number=line,
                    provider="GCP",
                    issue=None if enc else "NO_ENCRYPTION",
                )
            )
        elif rtype == "aws_acm_certificate":
            key_algo = re.search(r'key_algorithm\s*=\s*"([^"]+)"', body)
            raw = (key_algo.group(1) if key_algo else "RSA_2048").upper()
            algo = "RSA" if "RSA" in raw else ("ECDSA" if "EC" in raw else raw)
            bits = 2048 if "2048" in raw else (256 if "256" in raw else None)
            findings.append(
                cloud_finding(
                    source_type="AWS_ACM_CERTIFICATE",
                    resource=resource,
                    algorithm=algo,
                    key_size=bits,
                    purpose="TLS_CERTIFICATE",
                    file_path=str(path),
                    line_number=line,
                )
            )
        elif rtype == "aws_cloudfront_distribution":
            min_proto = re.search(r'minimum_protocol_version\s*=\s*"([^"]+)"', body)
            proto = (min_proto.group(1) if min_proto else "TLSv1").upper()
            weak = proto in {"TLSV1", "TLSV1.1", "SSLV3", "TLSV1_2016"}
            findings.append(
                cloud_finding(
                    source_type="AWS_CLOUDFRONT_DISTRIBUTION",
                    resource=resource,
                    algorithm="TLS1.0" if weak else "TLS",
                    purpose="LOAD_BALANCER_TLS",
                    file_path=str(path),
                    line_number=line,
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={"min_protocol": proto},
                )
            )
        elif rtype == "aws_secretsmanager_secret":
            findings.append(
                cloud_finding(
                    source_type="AWS_SECRETSMANAGER_SECRET",
                    resource=resource,
                    algorithm="AES-256",
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    line_number=line,
                )
            )
        elif rtype in {"aws_api_gateway_domain_name", "aws_apigatewayv2_domain_name"}:
            policy = re.search(r'security_policy\s*=\s*"([^"]+)"', body)
            name_policy = (policy.group(1) if policy else "TLS_1_0").upper()
            weak = "1_0" in name_policy or "1_1" in name_policy
            findings.append(
                cloud_finding(
                    source_type="AWS_API_GATEWAY",
                    resource=resource,
                    algorithm="TLS1.0" if weak else "TLS",
                    purpose="NETWORK_ENCRYPTION",
                    file_path=str(path),
                    line_number=line,
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={"security_policy": name_policy},
                )
            )
        elif rtype in {"azurerm_mssql_server", "azurerm_sql_server", "azurerm_mssql_database"}:
            tde = re.search(r"transparent_data_encryption_enabled\s*=\s*(true|false)", body)
            enabled = tde.group(1) != "false" if tde else True
            findings.append(
                cloud_finding(
                    source_type="AZURE_SQL_DATABASE",
                    resource=resource,
                    algorithm="AES-256" if enabled else None,
                    purpose="DATABASE_ENCRYPTION",
                    file_path=str(path),
                    line_number=line,
                    provider="AZURE",
                    issue=None if enabled else "NO_ENCRYPTION_AT_REST",
                )
            )
        elif rtype == "azurerm_application_gateway":
            min_tls = re.search(r'min_protocol_version\s*=\s*"([^"]+)"', body)
            version = (min_tls.group(1) if min_tls else "TLSv1_0").upper()
            weak = any(token in version for token in ("TLSV1_0", "TLSV1_1", "SSL"))
            findings.append(
                cloud_finding(
                    source_type="AZURE_APP_GATEWAY",
                    resource=resource,
                    algorithm="TLS1.0" if weak else "TLS",
                    purpose="LOAD_BALANCER_TLS",
                    file_path=str(path),
                    line_number=line,
                    provider="AZURE",
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={"min_protocol": version},
                )
            )
        elif rtype == "google_sql_database_instance":
            enc = "disk_encryption_configuration" in body or "encryption" in body
            findings.append(
                cloud_finding(
                    source_type="GCP_CLOUD_SQL",
                    resource=resource,
                    algorithm="AES-256" if enc else None,
                    purpose="DATABASE_ENCRYPTION",
                    file_path=str(path),
                    line_number=line,
                    provider="GCP",
                    issue=None if enc else "NO_ENCRYPTION_AT_REST",
                )
            )
        elif rtype == "google_compute_ssl_policy":
            min_tls = re.search(r'min_tls_version\s*=\s*"([^"]+)"', body)
            version = (min_tls.group(1) if min_tls else "TLS_1_0").upper()
            weak = version in {"TLS_1_0", "TLS_1_1", "TLSV1_0", "TLSV1_1"}
            findings.append(
                cloud_finding(
                    source_type="GCP_SSL_POLICY",
                    resource=resource,
                    algorithm="TLS1.0" if weak else "TLS",
                    purpose="LOAD_BALANCER_TLS",
                    file_path=str(path),
                    line_number=line,
                    provider="GCP",
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={"min_tls_version": version},
                )
            )
    return findings
