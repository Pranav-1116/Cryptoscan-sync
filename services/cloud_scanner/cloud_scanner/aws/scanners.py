"""AWS service scanners. Accept injected clients so unit tests do not need boto3."""

from __future__ import annotations

from typing import Any, Callable

from cloud_scanner.aws.mappers import (
    as_list,
    map_acm_key,
    map_kms_key_spec,
    map_s3_sse,
    min_tls_from_protocols,
    weak_tls_protocols,
)
from cloud_scanner.common.finding import cloud_finding

ClientFactory = Callable[[str, str], Any]


def _safe(call, default=None):
    try:
        return call()
    except Exception:
        return default


def scan_kms(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    keys = as_list((_safe(client.list_keys, {}) or {}).get("Keys"))
    for item in keys[:80]:
        key_id = item.get("KeyId")
        if not key_id:
            continue
        meta = ((_safe(lambda: client.describe_key(KeyId=key_id), {}) or {}).get("KeyMetadata")) or {}
        spec = meta.get("KeySpec") or "SYMMETRIC_DEFAULT"
        algo, bits = map_kms_key_spec(spec)
        rotation = _safe(lambda: client.get_key_rotation_status(KeyId=key_id), {}) or {}
        usage = meta.get("KeyUsage") or "ENCRYPT_DECRYPT"
        purpose = "SIGNING" if "SIGN" in usage else "KEY_MANAGEMENT"
        findings.append(
            cloud_finding(
                source_type="AWS_KMS_KEY",
                resource=meta.get("Arn") or key_id,
                algorithm=algo,
                key_size=bits,
                purpose=purpose,
                file_path=f"aws://{region}/kms/{key_id}",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "key_state": meta.get("KeyState"),
                    "key_spec": spec,
                    "origin": meta.get("Origin"),
                    "rotation_enabled": bool(rotation.get("KeyRotationEnabled")),
                    "key_manager": meta.get("KeyManager"),
                    "multi_region": bool(meta.get("MultiRegion")),
                },
            )
        )
    return findings


def scan_s3(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    buckets = as_list((_safe(client.list_buckets, {}) or {}).get("Buckets"))
    for bucket in buckets[:80]:
        name = bucket.get("Name")
        if not name:
            continue
        loc = _safe(lambda: client.get_bucket_location(Bucket=name), {}) or {}
        bucket_region = loc.get("LocationConstraint") or "us-east-1"
        if bucket_region not in {region, None} and region != "global":
            # Still report; S3 listing is global. Keep the bucket's region in metadata.
            pass
        issue = None
        algo = "AES-256"
        mode = None
        try:
            enc = client.get_bucket_encryption(Bucket=name)
            rules = (((enc or {}).get("ServerSideEncryptionConfiguration") or {}).get("Rules")) or []
            if rules:
                applied = (rules[0].get("ApplyServerSideEncryptionByDefault") or {})
                algo, mode = map_s3_sse(applied.get("SSEAlgorithm"))
        except Exception as exc:
            code = ""
            response = getattr(exc, "response", None)
            if isinstance(response, dict):
                code = ((response.get("Error") or {}).get("Code")) or ""
            if "NoEncryption" in str(exc) or code == "ServerSideEncryptionConfigurationNotFoundError":
                issue = "NO_ENCRYPTION"
                algo = None
            else:
                continue
        findings.append(
            cloud_finding(
                source_type="AWS_S3_BUCKET",
                resource=name,
                algorithm=algo,
                mode=mode,
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"aws://s3/{name}",
                issue=issue,
                extra={"region": bucket_region, "scan_method": "LIVE_API"},
            )
        )
    return findings


def scan_rds(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    instances = as_list((_safe(client.describe_db_instances, {}) or {}).get("DBInstances"))
    for db in instances[:80]:
        encrypted = bool(db.get("StorageEncrypted"))
        findings.append(
            cloud_finding(
                source_type="AWS_RDS_INSTANCE",
                resource=db.get("DBInstanceIdentifier") or db.get("DBInstanceArn") or "rds",
                algorithm="AES-256-XTS" if encrypted else None,
                purpose="DATABASE_ENCRYPTION",
                file_path=f"aws://{region}/rds/{db.get('DBInstanceIdentifier')}",
                issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "kms_key_id": db.get("KmsKeyId"),
                    "ssl_enabled": bool(db.get("CACertificateIdentifier")),
                },
            )
        )
    return findings


def scan_elb(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    balancers = as_list((_safe(client.describe_load_balancers, {}) or {}).get("LoadBalancers"))
    for lb in balancers[:40]:
        arn = lb.get("LoadBalancerArn")
        listeners = as_list(
            (_safe(lambda: client.describe_listeners(LoadBalancerArn=arn), {}) or {}).get("Listeners")
        )
        for listener in listeners:
            protocol = (listener.get("Protocol") or "").upper()
            if protocol not in {"HTTPS", "TLS"}:
                continue
            policy_name = listener.get("SslPolicy") or "DEFAULT"
            details = as_list(
                (_safe(lambda: client.describe_ssl_policies(Names=[policy_name]), {}) or {}).get("SslPolicies")
            )
            protocols = []
            if details:
                protocols = [p.get("Name") if isinstance(p, dict) else str(p) for p in (details[0].get("SslProtocols") or [])]
                if not protocols:
                    protocols = list(details[0].get("SslProtocols") or [])
            weak = weak_tls_protocols(protocols) or any(
                token in policy_name.upper() for token in ("TLS-1-0", "TLS-1-1", "SSL")
            )
            algo = min_tls_from_protocols(protocols) if protocols else ("TLS1.0" if weak else "TLS")
            findings.append(
                cloud_finding(
                    source_type="AWS_ELB_LISTENER",
                    resource=listener.get("ListenerArn") or arn,
                    algorithm=algo,
                    purpose="LOAD_BALANCER_TLS",
                    file_path=f"aws://{region}/elb/{lb.get('LoadBalancerName') or arn}",
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={
                        "region": region,
                        "scan_method": "LIVE_API",
                        "ssl_policy": policy_name,
                        "protocols": protocols,
                        "certificates": [c.get("CertificateArn") for c in (listener.get("Certificates") or [])],
                    },
                )
            )
    return findings


def scan_acm(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    summaries = as_list((_safe(client.list_certificates, {}) or {}).get("CertificateSummaryList"))
    for item in summaries[:80]:
        arn = item.get("CertificateArn")
        if not arn:
            continue
        cert = ((_safe(lambda: client.describe_certificate(CertificateArn=arn), {}) or {}).get("Certificate")) or {}
        algo, bits = map_acm_key(cert.get("KeyAlgorithm"))
        status = (cert.get("Status") or "").upper()
        issue = None
        if status == "EXPIRED":
            issue = "CERT_EXPIRED"
        findings.append(
            cloud_finding(
                source_type="AWS_ACM_CERTIFICATE",
                resource=arn,
                algorithm=algo,
                key_size=bits,
                purpose="TLS_CERTIFICATE",
                file_path=f"aws://{region}/acm/{cert.get('DomainName') or arn}",
                issue=issue,
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "domain_name": cert.get("DomainName"),
                    "status": cert.get("Status"),
                    "signature_algorithm": cert.get("SignatureAlgorithm"),
                    "not_after": str(cert.get("NotAfter") or ""),
                    "in_use_by": cert.get("InUseBy") or [],
                    "type": cert.get("Type"),
                },
            )
        )
    return findings


def scan_cloudfront(client, *, region: str = "global") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    items = as_list(((_safe(client.list_distributions, {}) or {}).get("DistributionList") or {}).get("Items"))
    for dist in items[:40]:
        viewer = dist.get("ViewerCertificate") or {}
        proto = (viewer.get("MinimumProtocolVersion") or "TLSv1").upper()
        weak = any(token in proto for token in ("SSL", "TLSV1", "TLSV1.1", "TLSV1_0", "TLSV1_1")) and "TLSV1.2" not in proto and "TLSV1.3" not in proto
        if proto in {"TLSv1", "TLSv1.1", "SSLv3"}:
            weak = True
        findings.append(
            cloud_finding(
                source_type="AWS_CLOUDFRONT_DISTRIBUTION",
                resource=dist.get("ARN") or dist.get("Id") or "cloudfront",
                algorithm="TLS1.0" if weak else "TLS",
                purpose="LOAD_BALANCER_TLS",
                file_path=f"aws://cloudfront/{dist.get('Id')}",
                issue="WEAK_TLS_VERSION" if weak else None,
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "min_protocol": proto,
                    "domain": dist.get("DomainName"),
                },
            )
        )
    return findings


def scan_secretsmanager(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    secrets = as_list((_safe(client.list_secrets, {}) or {}).get("SecretList"))
    for secret in secrets[:80]:
        name = secret.get("Name") or secret.get("ARN")
        kms = secret.get("KmsKeyId")
        findings.append(
            cloud_finding(
                source_type="AWS_SECRETSMANAGER_SECRET",
                resource=secret.get("ARN") or name,
                algorithm="AES-256" if kms or True else None,
                purpose="KEY_MANAGEMENT",
                file_path=f"aws://{region}/secrets/{name}",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "kms_key_id": kms,
                    "rotation_enabled": bool(secret.get("RotationEnabled")),
                },
            )
        )
    return findings


def scan_lambda(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    functions = as_list((_safe(client.list_functions, {}) or {}).get("Functions"))
    for fn in functions[:80]:
        name = fn.get("FunctionName") or fn.get("FunctionArn") or "lambda"
        env = fn.get("Environment") or {}
        kms = fn.get("KMSKeyArn") or env.get("KMSKeyArn")
        tracing = ((fn.get("TracingConfig") or {}).get("Mode") or "").upper()
        runtime = fn.get("Runtime") or ""
        issue = None if kms else "NO_ENV_ENCRYPTION"
        findings.append(
            cloud_finding(
                source_type="AWS_LAMBDA_FUNCTION",
                resource=fn.get("FunctionArn") or name,
                algorithm="AES-256" if kms else None,
                purpose="KEY_MANAGEMENT",
                file_path=f"aws://{region}/lambda/{name}",
                issue=issue,
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "runtime": runtime,
                    "kms_key_arn": kms,
                    "tracing": tracing,
                    "memory_size": fn.get("MemorySize"),
                    "timeout": fn.get("Timeout"),
                    "package_type": fn.get("PackageType"),
                    "architectures": fn.get("Architectures") or [],
                },
            )
        )
    return findings


def scan_apigateway(client, *, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    apis = as_list((_safe(client.get_rest_apis, {}) or {}).get("items"))
    for api in apis[:40]:
        api_id = api.get("id")
        stages = as_list((_safe(lambda: client.get_stages(restApiId=api_id), {}) or {}).get("item"))
        for stage in stages or [{"stageName": "default"}]:
            settings = stage.get("methodSettings") or {}
            findings.append(
                cloud_finding(
                    source_type="AWS_API_GATEWAY",
                    resource=f"{api.get('name') or api_id}/{stage.get('stageName')}",
                    algorithm="TLS",
                    purpose="NETWORK_ENCRYPTION",
                    file_path=f"aws://{region}/apigateway/{api_id}",
                    extra={
                        "region": region,
                        "scan_method": "LIVE_API",
                        "stage": stage.get("stageName"),
                        "client_certificate_id": stage.get("clientCertificateId"),
                        "method_settings": bool(settings),
                    },
                )
            )
    return findings
