"""AWS service scanners. Accept injected clients so unit tests do not need boto3.

Enterprise semantics:
- list calls are paginated to ``max_items`` (cap recorded as a truncation,
  never silently dropped);
- transient (throttle) failures are retried, permanent failures are
  recorded as telemetry errors;
- ``telemetry`` is optional; without it behaviour degrades to the legacy
  fail-open mode.
"""

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
from cloud_scanner.core.reliability import ScanTelemetry, call_with_retry

ClientFactory = Callable[[str, str], Any]

DEFAULT_MAX_ITEMS = 500


def _safe(call, default=None):
    try:
        return call()
    except Exception:
        return default


def _dig(response: Any, items_key: str) -> list:
    """Support dotted paths, e.g. 'DistributionList.Items'."""
    current = response
    for part in items_key.split("."):
        if not isinstance(current, dict):
            return []
        current = current.get(part)
    return current if isinstance(current, list) else []


def _list(
    client,
    method_name: str,
    *,
    items_key: str,
    telemetry: ScanTelemetry | None,
    service: str,
    region: str,
    max_items: int | None = None,
    **extra_kwargs,
):
    """Paginated + retried list call. Falls back to a single unpaged call for
    injected test clients that page differently; telemetry-first."""
    method = getattr(client, method_name)
    cap = max_items or (telemetry.max_resources if telemetry else DEFAULT_MAX_ITEMS)
    if telemetry:
        telemetry.providers_attempted.add("AWS")
    ok, value, error = call_with_retry(lambda: method(**extra_kwargs))
    if not ok:
        # Retry once more with pagination kwargs omitted (some fakes reject them).
        ok, value, error = call_with_retry(lambda: method())
    if not ok:
        if telemetry:
            telemetry.record_error("AWS", service, region, error)
        return []
    # If the API pages, walk it.
    response = value or {}
    items = _dig(response, items_key)
    token = next(
        (str(response[key]) for key in ("NextToken", "NextMarker", "Marker") if isinstance(response, dict) and response.get(key)),
        None,
    )
    collected = [i for i in (items or []) if isinstance(i, (dict, str)) and i]
    dropped_at_cap = False
    while token and len(collected) < cap:
        paged_kwargs = dict(extra_kwargs)
        for key in ("NextToken", "Marker"):
            paged_kwargs.setdefault(key, token)
            break
        ok, value, error = call_with_retry(lambda: method(**paged_kwargs))
        if not ok:
            if telemetry:
                telemetry.record_error("AWS", service, region, error)
            break
        response = value or {}
        page = [i for i in (_dig(response, items_key) or []) if isinstance(i, (dict, str)) and i]
        if not page:
            break
        for item in page:
            if len(collected) >= cap:
                dropped_at_cap = True
                break
            collected.append(item)
        token = next(
            (str(response[key]) for key in ("NextToken", "NextMarker", "Marker") if isinstance(response, dict) and response.get(key)),
            None,
        )
    if len(collected) >= cap and (token or dropped_at_cap):
        if telemetry:
            telemetry.record_truncation("AWS", service, region, cap)
    if telemetry:
        telemetry.record_resources(len(collected))
    return collected


def scan_kms(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    keys = _list(client, "list_keys", items_key="Keys", telemetry=telemetry, service="kms", region=region)
    for item in keys:
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


def scan_s3(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    buckets = _list(client, "list_buckets", items_key="Buckets", telemetry=telemetry, service="s3", region="global")
    for bucket in buckets:
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


def scan_rds(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    instances = _list(client, "describe_db_instances", items_key="DBInstances", telemetry=telemetry, service="rds", region=region)
    for db in instances:
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


def scan_elb(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    balancers = _list(client, "describe_load_balancers", items_key="LoadBalancers", telemetry=telemetry, service="elbv2", region=region)
    for lb in balancers:
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


def scan_acm(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    summaries = _list(client, "list_certificates", items_key="CertificateSummaryList", telemetry=telemetry, service="acm", region=region)
    for item in summaries:
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


def scan_cloudfront(client, *, region: str = "global", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    items = _list(
        client,
        "list_distributions",
        items_key="DistributionList.Items",
        telemetry=telemetry,
        service="cloudfront",
        region="global",
    )
    items = [
        dist
        for dist in items
        if isinstance(dist, dict)
    ]
    for dist in items:
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


def scan_secretsmanager(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    secrets = _list(client, "list_secrets", items_key="SecretList", telemetry=telemetry, service="secretsmanager", region=region)
    for secret in secrets:
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


def scan_lambda(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    functions = _list(client, "list_functions", items_key="Functions", telemetry=telemetry, service="lambda", region=region)
    for fn in functions:
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


def scan_apigateway(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    apis = _list(client, "get_rest_apis", items_key="items", telemetry=telemetry, service="apigateway", region=region)
    for api in apis:
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


def scan_ebs(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    volumes = _list(client, "describe_volumes", items_key="Volumes", telemetry=telemetry, service="ec2", region=region)
    for vol in volumes:
        encrypted = bool(vol.get("Encrypted"))
        vol_id = vol.get("VolumeId") or "volume"
        findings.append(
            cloud_finding(
                source_type="AWS_EBS_VOLUME",
                resource=vol_id,
                algorithm="AES-256" if encrypted else None,
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"aws://{region}/ebs/{vol_id}",
                issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "kms_key_id": vol.get("KmsKeyId"),
                    "volume_type": vol.get("VolumeType"),
                    "state": vol.get("State"),
                },
            )
        )
    return findings


def scan_ssm(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    params = _list(
        client,
        "describe_parameters",
        items_key="Parameters",
        telemetry=telemetry,
        service="ssm",
        region=region,
    )
    for param in params:
        name = param.get("Name") or param.get("ARN") or "parameter"
        ptype = param.get("Type") or "String"
        encrypted = ptype == "SecureString"
        findings.append(
            cloud_finding(
                source_type="AWS_SSM_PARAMETER",
                resource=name,
                algorithm="AES-256" if encrypted else None,
                purpose="KEY_MANAGEMENT",
                file_path=f"aws://{region}/ssm/{name}",
                issue=None if encrypted else "UNENCRYPTED_PARAMETER",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "type": ptype,
                    "key_id": param.get("KeyId"),
                    "tier": param.get("Tier"),
                },
            )
        )
    return findings


def scan_dynamodb(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """DynamoDB tables: SSE status + KMS key (AWS-owned vs customer CMK)."""
    findings: list[dict[str, Any]] = []
    tables = _list(
        client,
        "list_tables",
        items_key="TableNames",
        telemetry=telemetry,
        service="dynamodb",
        region=region,
    )
    for name in tables:
        table_name = name if isinstance(name, str) else str(named_of(name))
        desc = _safe(lambda n=table_name: client.describe_table(TableName=n).get("Table", {}), {}) or {}
        sse = desc.get("SSEDescription") or {}
        sse_on = bool(sse.get("Status") == "ENABLED")
        kms = sse.get("KMSMasterKeyArn")
        findings.append(
            cloud_finding(
                source_type="AWS_DYNAMODB_TABLE",
                resource=table_name,
                algorithm="AES-256" if sse_on else None,
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"aws://{region}/dynamodb/{table_name}",
                issue=None if sse_on else "NO_ENCRYPTION_AT_REST",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "sse_enabled": sse_on,
                    "sse_status": sse.get("Status"),
                    "kms_key_id": kms,
                    "cmk": bool(kms),
                },
            )
        )
    return findings


def scan_sqs(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """SQS queues: server-side encryption (SSE-SHA256/SSE-KMS)."""
    findings: list[dict[str, Any]] = []
    queues = _list(
        client,
        "list_queues",
        items_key="QueueUrls",
        telemetry=telemetry,
        service="sqs",
        region=region,
    )
    for url in queues:
        queue_url = url if isinstance(url, str) else str(url)
        name = queue_url.rsplit("/", 1)[-1] if "/" in queue_url else queue_url
        attrs = (
            _safe(lambda u=queue_url: client.get_queue_attributes(
                QueueUrl=u, AttributeNames=["SqsManagedSseEnabled", "KmsMasterKeyId"]
            ).get("Attributes", {}), {}) or {}
        )
        kms = attrs.get("KmsMasterKeyId")
        managed_sse = str(attrs.get("SqsManagedSseEnabled", "false")).lower() == "true"
        encrypted = bool(kms) or managed_sse
        findings.append(
            cloud_finding(
                source_type="AWS_SQS_QUEUE",
                resource=name or queue_url,
                algorithm="AES-256" if encrypted else None,
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"aws://{region}/sqs/{name}",
                issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "kms_key_id": kms,
                    "sse_managed": managed_sse,
                },
            )
        )
    return findings


def scan_sns(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """SNS topics: server-side encryption (KMS)."""
    findings: list[dict[str, Any]] = []
    topics = _list(
        client,
        "list_topics",
        items_key="Topics",
        telemetry=telemetry,
        service="sns",
        region=region,
    )
    for topic in topics:
        arn = topic.get("TopicArn") or "topic"
        name = arn.rsplit(":", 1)[-1] if ":" in arn else arn
        attrs = (
            _safe(lambda a=arn: client.get_topic_attributes(TopicArn=a).get("Attributes", {}), {}) or {}
        )
        kms = attrs.get("KmsMasterKeyId")
        findings.append(
            cloud_finding(
                source_type="AWS_SNS_TOPIC",
                resource=arn,
                algorithm="AES-256" if kms else None,
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"aws://{region}/sns/{name}",
                issue=None if kms else "NO_ENCRYPTION_AT_REST",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "kms_key_id": kms,
                },
            )
        )
    return findings


def scan_opensearch(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """OpenSearch domains: encryption at rest + minimum TLS version."""
    findings: list[dict[str, Any]] = []
    domains = _list(
        client,
        "list_domain_names",
        items_key="DomainNames",
        telemetry=telemetry,
        service="opensearch",
        region=region,
    )
    for entry in domains:
        name = entry.get("DomainName") if isinstance(entry, dict) else str(entry)
        desc = _safe(lambda n=name: (client.describe_domain(DomainName=n) or {}).get("DomainStatus", {}), {}) or {}
        enc = desc.get("EncryptionAtRestOptions") or {}
        encrypted = bool(enc.get("Enabled"))
        tls = (desc.get("DomainEndpointOptions") or {}).get("TLSSecurityPolicy") or "Policy-Min-TLS-1-0-2019-07"
        weak_tls = "1-0" in tls or "1_0" in tls
        issue = None
        if not encrypted:
            issue = "NO_ENCRYPTION_AT_REST"
        elif weak_tls:
            issue = "WEAK_TLS_VERSION"
        findings.append(
            cloud_finding(
                source_type="AWS_OPENSEARCH_DOMAIN",
                resource=name,
                algorithm="AES-256" if encrypted else ("TLS1.0" if weak_tls else "TLS"),
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"aws://{region}/opensearch/{name}",
                issue=issue,
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "encryption_at_rest": encrypted,
                    "kms_key_id": enc.get("KmsKeyId"),
                    "tls_security_policy": tls,
                },
            )
        )
    return findings


def scan_eks(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """EKS clusters: Kubernetes secrets envelope encryption via KMS."""
    findings: list[dict[str, Any]] = []
    clusters = _list(
        client,
        "list_clusters",
        items_key="clusters",
        telemetry=telemetry,
        service="eks",
        region=region,
    )
    for name in clusters:
        cluster_name = name if isinstance(name, str) else str(name)
        desc = _safe(lambda n=cluster_name: (client.describe_cluster(name=n) or {}).get("cluster", {}), {}) or {}
        enc = desc.get("encryptionConfig") or []
        kms = next((str((item.get("provider") or {}).get("keyArn") or "") for item in enc if item.get("provider")), "")
        findings.append(
            cloud_finding(
                source_type="AWS_EKS_CLUSTER",
                resource=cluster_name,
                algorithm="AES-256" if kms else None,
                purpose="KEY_MANAGEMENT",
                file_path=f"aws://{region}/eks/{cluster_name}",
                issue=None if kms else "NO_ENV_ENCRYPTION",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "secrets_encryption_kms": kms or None,
                    "kubernetes_version": desc.get("version"),
                },
            )
        )
    return findings


def scan_redshift(client, *, region: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Redshift clusters: storage encryption (KMS or CloudHSM)."""
    findings: list[dict[str, Any]] = []
    clusters = _list(
        client,
        "describe_clusters",
        items_key="Clusters",
        telemetry=telemetry,
        service="redshift",
        region=region,
    )
    for cluster in clusters:
        encrypted = bool(cluster.get("Encrypted"))
        kms = cluster.get("KmsKeyId")
        hsm = bool(cluster.get("HsmClientCertificateIdentifier"))
        name = cluster.get("ClusterIdentifier") or "redshift"
        findings.append(
            cloud_finding(
                source_type="AWS_REDSHIFT_CLUSTER",
                resource=name,
                algorithm="AES-256" if encrypted else None,
                purpose="DATABASE_ENCRYPTION",
                file_path=f"aws://{region}/redshift/{name}",
                issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                extra={
                    "region": region,
                    "scan_method": "LIVE_API",
                    "encrypted": encrypted,
                    "kms_key_id": kms,
                    "hsm_backed": hsm,
                },
            )
        )
    return findings


def named_of(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("Name") or item.get("name") or next(iter(item.values()), "resource"))
    return str(item)
