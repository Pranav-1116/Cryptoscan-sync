"""GCP service scanners. Accept injected clients so unit tests do not need SDKs."""

from __future__ import annotations

from typing import Any

from cloud_scanner.common.finding import cloud_finding
from cloud_scanner.common.objects import attr, iter_records, named, safe
from cloud_scanner.core.reliability import ScanTelemetry, cap_items


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


def scan_cloud_kms(client: Any, *, project: str, location: str = "global", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    keys: list[Any] = []
    if isinstance(client, list):
        keys = client
    elif hasattr(client, "list_crypto_keys"):
        parent = f"projects/{project}/locations/{location}"
        if hasattr(client, "list_key_rings"):
            rings = iter_records(safe(lambda: client.list_key_rings(request={"parent": parent}), []))
            if rings:
                for ring in cap_items(rings, telemetry=telemetry, provider="GCP", service="kms-keyrings", region=location):
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
    for key in cap_items(keys, telemetry=telemetry, provider="GCP", service="kms", region=location):
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


def scan_gcs(client: Any, *, project: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    buckets = _records(client, "list_buckets")
    if not buckets and hasattr(client, "list_buckets"):
        buckets = iter_records(safe(client.list_buckets, []))
    for bucket in cap_items(buckets, telemetry=telemetry, provider="GCP", service="storage", region=project):
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


def scan_cloud_sql(client: Any, *, project: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
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
    for inst in cap_items(items, telemetry=telemetry, provider="GCP", service="sql", region=project):
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


def scan_load_balancer(client: Any, *, project: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
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
    for policy in cap_items(items, telemetry=telemetry, provider="GCP", service="sslpolicy", region=project):
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


def scan_secret_manager(client: Any, *, project: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Secret Manager secrets: CMEK + replication status."""
    findings: list[dict[str, Any]] = []
    secrets: list[Any] = []
    if isinstance(client, list):
        secrets = client
    elif hasattr(client, "list_secrets"):
        parent = f"projects/{project}"
        secrets = iter_records(safe(lambda: client.list_secrets(request={"parent": parent}), []))
    else:
        secrets = _records(client, "list")
    for secret in cap_items(secrets, telemetry=telemetry, provider="GCP", service="secretmanager", region=project):
        name = named(secret) or str(attr(secret, "name", default="secret") or "secret")
        short = name.rsplit("/", 1)[-1]
        if isinstance(secret, dict):
            replication = secret.get("replication") or {}
            kms = str(replication.get("customerManagedEncryption", {}).get("kmsKeyName") or "")
        else:
            repl = attr(secret, "replication") or {}
            cme = attr(repl, "customer_managed_encryption", "customerManagedEncryption") or {}
            kms = str(attr(cme, "kms_key_name", "kmsKeyName") or "")
        findings.append(
            cloud_finding(
                source_type="GCP_SECRET_MANAGER_SECRET",
                resource=short,
                algorithm="AES-256" if kms else "AES-256-GCM",
                purpose="KEY_MANAGEMENT",
                file_path=f"gcp://secretmanager/{short}",
                provider="GCP",
                extra={
                    "project": project,
                    "scan_method": "LIVE_API",
                    "customer_managed_key": bool(kms),
                    "kms_key_name": kms or None,
                },
            )
        )
    return findings


def scan_pubsub(client: Any, *, project: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Pub/Sub topics: CMEK encryption of message payloads."""
    findings: list[dict[str, Any]] = []
    topics: list[Any] = []
    if isinstance(client, list):
        topics = client
    elif hasattr(client, "list_topics"):
        parent = f"projects/{project}"
        topics = iter_records(safe(lambda: client.list_topics(request={"project": parent}), []))
    else:
        topics = _records(client, "list")
    for topic in cap_items(topics, telemetry=telemetry, provider="GCP", service="pubsub", region=project):
        name = named(topic) or str(attr(topic, "name", default="topic") or "topic")
        short = name.rsplit("/", 1)[-1]
        if isinstance(topic, dict):
            kms = str((topic.get("kms_key_name") or topic.get("kmsKeyName")) or "")
        else:
            kms = str(attr(topic, "kms_key_name", "kmsKeyName") or "")
        findings.append(
            cloud_finding(
                source_type="GCP_PUBSUB_TOPIC",
                resource=short,
                algorithm="AES-256" if kms else None,
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"gcp://pubsub/{short}",
                provider="GCP",
                issue=None if kms else "NO_ENCRYPTION_AT_REST",
                extra={
                    "project": project,
                    "scan_method": "LIVE_API",
                    "kms_key_name": kms or None,
                },
            )
        )
    return findings


def scan_gke(client: Any, *, project: str, telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """GKE clusters: application-layer secrets encryption via Cloud KMS."""
    findings: list[dict[str, Any]] = []
    clusters: list[Any] = []
    if isinstance(client, list):
        clusters = client
    elif hasattr(client, "projects"):
        # googleapiclient Resource (attributes) or lightweight injected fakes
        # (callable factories) — walk projects().locations().clusters() either way.
        parent = f"projects/{project}/locations/-"
        projects = client.projects() if callable(client.projects) else client.projects
        locations = projects.locations() if callable(projects.locations) else projects.locations
        cluster_api = locations.clusters() if callable(locations.clusters) else locations.clusters
        listed = cluster_api.list(parent=parent)
        payload = listed.execute() if hasattr(listed, "execute") else listed
        clusters = iter_records((payload or {}).get("clusters") if isinstance(payload, dict) else payload)
    else:
        clusters = _records(client, "list")
    for cluster in cap_items(clusters, telemetry=telemetry, provider="GCP", service="gke", region=project):
        name = named(cluster, "cluster")
        if isinstance(cluster, dict):
            enc = (cluster.get("encryptionConfig") or {}).get("keyName") or ""
            version = cluster.get("initialClusterVersion")
        else:
            enc = str(attr(attr(cluster, "encryption_config", "encryptionConfig"), "key_name", "keyName") or "")
            version = attr(cluster, "initial_cluster_version", "initialClusterVersion")
        findings.append(
            cloud_finding(
                source_type="GCP_GKE_CLUSTER",
                resource=name,
                algorithm="AES-256" if enc else None,
                purpose="KEY_MANAGEMENT",
                file_path=f"gcp://gke/{name}",
                provider="GCP",
                issue=None if enc else "NO_ENV_ENCRYPTION",
                extra={
                    "project": project,
                    "scan_method": "LIVE_API",
                    "secrets_encryption_kms": enc or None,
                    "gke_version": version,
                },
            )
        )
    return findings
