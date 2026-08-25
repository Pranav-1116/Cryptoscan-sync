"""GCP service scanners. Accept injected clients so unit tests do not need SDKs."""

from __future__ import annotations

from typing import Any

from cloud_scanner.common.finding import cloud_finding
from cloud_scanner.common.objects import attr, iter_records, named, safe


def _records(client: Any, *path: str) -> list[Any]:
    if isinstance(client, list):
        return client
    current = client
    for name in path:
        if current is None:
            return []
        nxt = attr(current, name)
        if callable(nxt):
            current = safe(lambda n=nxt: n(), [])
        else:
            current = nxt
    if callable(current):
        current = safe(current, [])
    return iter_records(current)


def map_gcp_kms_algorithm(raw: str | None) -> tuple[str, int | None]:
    token = (raw or "GOOGLE_SYMMETRIC_ENCRYPTION").upper()
    if "RSA" in token:
        bits = 4096 if "4096" in token else (3072 if "3072" in token else 2048)
        return "RSA", bits
    if "EC_" in token or "ECDSA" in token or "EC_SIGN" in token:
        bits = 384 if "P384" in token else (521 if "P521" in token else 256)
        return "ECDSA", bits
    return "AES-256", 256


def _algo_name(key: Any) -> str:
    template = attr(key, "version_template") or key
    algo = attr(template, "algorithm", "crypto_algorithm")
    if algo is None:
        return str(attr(key, "algorithm", default="GOOGLE_SYMMETRIC_ENCRYPTION") or "GOOGLE_SYMMETRIC_ENCRYPTION")
    if isinstance(algo, str):
        return algo
    return str(attr(algo, "name", default="") or algo)


def scan_cloud_kms(client: Any, *, project: str, location: str = "global") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    keys: list[Any] = []
    if isinstance(client, list):
        keys = client
    elif hasattr(client, "list_crypto_keys"):
        parent = f"projects/{project}/locations/{location}"
        if hasattr(client, "list_key_rings"):
            rings = iter_records(safe(lambda: client.list_key_rings(request={"parent": parent}), []))
            if rings:
                for ring in rings[:20]:
                    ring_name = named(ring) or attr(ring, "name") or parent
                    keys.extend(
                        iter_records(safe(lambda r=ring_name: client.list_crypto_keys(request={"parent": r}), []))
                    )
            else:
                keys = iter_records(safe(lambda: client.list_crypto_keys(request={"parent": parent}), []))
        else:
            keys = iter_records(safe(lambda: client.list_crypto_keys(request={"parent": parent}), []))
    else:
        keys = _records(client, "list")
    for key in keys[:40]:
        name = named(key) or str(attr(key, "name", default="key") or "key")
        algo_name = _algo_name(key)
        algo, bits = map_gcp_kms_algorithm(algo_name)
        template = attr(key, "version_template") or key
        protection = attr(template, "protection_level")
        protection_name = protection if isinstance(protection, str) else attr(protection, "name", default="")
        purpose = attr(key, "purpose")
        purpose_name = purpose if isinstance(purpose, str) else attr(purpose, "name", default="ENCRYPT_DECRYPT")
        rotation = attr(key, "rotation_period")
        rotation_seconds = attr(rotation, "seconds") if rotation is not None else None
        findings.append(
            cloud_finding(
                source_type="GCP_KMS_KEY",
                resource=name,
                algorithm=algo,
                key_size=bits,
                purpose="KEY_MANAGEMENT",
                file_path=f"gcp://kms/{name}",
                provider="GCP",
                extra={
                    "project": project,
                    "scan_method": "LIVE_API",
                    "algorithm": algo_name,
                    "protection_level": protection_name,
                    "kms_purpose": purpose_name,
                    "rotation_period_seconds": rotation_seconds,
                },
            )
        )
    return findings


def scan_gcs(client: Any, *, project: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    buckets = _records(client, "list_buckets")
    if not buckets and hasattr(client, "list_buckets"):
        buckets = iter_records(safe(client.list_buckets, []))
    for bucket in buckets[:40]:
        name = named(bucket, "bucket")
        kms_name = attr(bucket, "default_kms_key_name", "defaultKmsKeyName", "kms_key_name")
        findings.append(
            cloud_finding(
                source_type="GCP_STORAGE_BUCKET",
                resource=name,
                algorithm="AES-256",
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"gcp://storage/{name}",
                provider="GCP",
                extra={
                    "project": project,
                    "scan_method": "LIVE_API",
                    "default_kms": kms_name,
                    "cmek": bool(kms_name),
                },
            )
        )
    return findings


def scan_cloud_sql(client: Any, *, project: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    items: list[Any] = []
    if isinstance(client, list):
        items = client
    elif hasattr(client, "instances"):
        inst = client.instances()
        listed = inst.list(project=project) if hasattr(inst, "list") else inst
        payload = listed.execute() if hasattr(listed, "execute") else listed
        items = iter_records((payload or {}).get("items") if isinstance(payload, dict) else payload)
    else:
        items = _records(client, "list")
    for inst in items[:30]:
        name = named(inst, "sql") if not isinstance(inst, dict) else (inst.get("name") or "sql")
        if isinstance(inst, dict):
            settings = inst.get("settings") or {}
            encrypted = bool(settings.get("diskEncryptionConfiguration") or settings.get("diskEncryptionStatus") or True)
            version = inst.get("databaseVersion")
        else:
            settings = attr(inst, "settings") or {}
            encrypted = bool(
                attr(settings, "diskEncryptionConfiguration", "disk_encryption_configuration")
                or attr(inst, "encrypted", default=True)
            )
            version = attr(inst, "database_version", "databaseVersion")
        findings.append(
            cloud_finding(
                source_type="GCP_CLOUD_SQL",
                resource=name,
                algorithm="AES-256" if encrypted else None,
                purpose="DATABASE_ENCRYPTION",
                file_path=f"gcp://sql/{name}",
                provider="GCP",
                issue=None if encrypted else "NO_ENCRYPTION_AT_REST",
                extra={"project": project, "scan_method": "LIVE_API", "database_version": version},
            )
        )
    return findings


def scan_load_balancer(client: Any, *, project: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    items: list[Any] = []
    if isinstance(client, list):
        items = client
    elif hasattr(client, "sslPolicies"):
        listed = client.sslPolicies().list(project=project)
        payload = listed.execute() if hasattr(listed, "execute") else listed
        items = iter_records((payload or {}).get("items") if isinstance(payload, dict) else payload)
    else:
        items = _records(client, "list")
    for policy in items[:30]:
        if isinstance(policy, dict):
            name = policy.get("name") or "ssl-policy"
            version = (policy.get("minTlsVersion") or policy.get("min_tls_version") or "TLS_1_2").upper()
        else:
            name = named(policy, "ssl-policy")
            version = str(attr(policy, "min_tls_version", "minTlsVersion", default="TLS_1_2") or "TLS_1_2").upper()
        weak = version in {"TLS_1_0", "TLS_1_1", "TLS1_0", "TLS1_1", "TLSV1", "TLSV1.0", "TLSV1.1"}
        findings.append(
            cloud_finding(
                source_type="GCP_SSL_POLICY",
                resource=name,
                algorithm="TLS1.0" if weak else "TLS",
                purpose="LOAD_BALANCER_TLS",
                file_path=f"gcp://sslpolicy/{name}",
                provider="GCP",
                issue="WEAK_TLS_VERSION" if weak else None,
                extra={"project": project, "scan_method": "LIVE_API", "min_tls_version": version},
            )
        )
    return findings
