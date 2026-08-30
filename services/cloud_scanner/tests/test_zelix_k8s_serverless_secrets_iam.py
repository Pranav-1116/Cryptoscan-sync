"""ZELNX §9 Kubernetes + §10 serverless + §11 secrets + §12 IAM."""

from __future__ import annotations

from cloud_scanner.enterprise.iam_access import IamAccessDiscovery
from cloud_scanner.enterprise.kubernetes_crypto import KubernetesCryptoDiscovery
from cloud_scanner.enterprise.secret_refs import SecretReferenceDiscovery
from cloud_scanner.enterprise.serverless_crypto import (
    ServerlessCryptoDiscovery,
    detect_crypto_libraries,
)

from zelix_fixtures import all_providers


# ------------------------------------------------------------------ §9 k8s


def test_kubernetes_cluster_discovery():
    k8s = KubernetesCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert k8s.count() == 3  # eks + aks + gke
    assert k8s.count("aws") == 1
    assert k8s.count("azure") == 1
    assert k8s.count("gcp") == 1


def test_kubernetes_secrets_and_etcd_encryption():
    k8s = KubernetesCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    cluster = next(c for c in k8s.clusters if c.cluster_id == "eks-bank")
    assert cluster.secrets_encryption == "KMS_ENCRYPTED"
    assert cluster.secrets_key_reference == "arn:aws:kms:key-2"
    assert cluster.etcd_encryption == "ENABLED"
    assert cluster.api_tls_version == "TLSv1.3"
    assert cluster.api_tls_weak is False


def test_kubernetes_api_tls_weak_flag():
    k8s = KubernetesCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    cluster = next(c for c in k8s.clusters if c.cluster_id == "aks-payments")
    # api tls 1.2 is not weak by policy
    assert cluster.api_tls_weak is False
    assert len(k8s.weak_api_tls()) == 0


def test_kubernetes_ingress_tls():
    k8s = KubernetesCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    cluster = next(c for c in k8s.clusters if c.cluster_id == "eks-bank")
    assert len(cluster.ingress_tls) == 1
    ingress = cluster.ingress_tls[0]
    assert ingress.host == "bank.example"
    assert ingress.certificate_id == "arn:aws:acm:cert-1"
    assert ingress.issuer == "ca-issuer"
    assert ingress.secret_name == "tls-bank"


def test_kubernetes_workloads_and_mesh():
    k8s = KubernetesCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    cluster = next(c for c in k8s.clusters if c.cluster_id == "eks-bank")
    assert cluster.mesh == "ISTIO"
    assert cluster.mesh_mtls == "STRICT"
    workload = cluster.workloads[0]
    assert workload.workload == "banking-agent"
    assert workload.crypto_libraries == ["openssl"]
    assert workload.key_references == ["arn:aws:kms:key-2"]
    assert workload.image == "banking-agent:1.2.0"
    assert workload.image_digest == "sha256:abc"
    assert workload.identity == "iam-role-bank"
    assert workload.mtls is None


def test_kubernetes_unencrypted_secrets_detection():
    rows = {
        "clusters": [
            {"cluster_id": "c1", "secrets_encryption": "DISABLED",
             "api_tls_version": "TLSv1.3"},
            {"cluster_id": "c2", "secrets_encryption": "KMS_ENCRYPTED",
             "api_tls_version": "TLSv1.3"},
        ]
    }
    from cloud_scanner.enterprise.providers import fake_provider

    k8s = KubernetesCryptoDiscovery([fake_provider("aws", rows).to_provider_entry()]).discover()
    assert [c.cluster_id for c in k8s.unencrypted_secrets()] == ["c1"]


def test_kubernetes_summary():
    k8s = KubernetesCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    summary = k8s.summary()
    assert summary["clusters"] == 3
    assert summary["workloads"] == 2
    assert summary["ingress_hosts"] == 1


# ------------------------------------------------------------------ §10 serverless


def test_serverless_discovery():
    sl = ServerlessCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert sl.count() == 2  # aws lambda + azure function
    fn = next(f for f in sl.functions if f.function_id == "lambda-pay")
    assert fn.runtime == "python3.12"
    assert fn.key_references == ["arn:aws:kms:key-1"]
    assert fn.certificate_references == ["arn:aws:acm:cert-1"]
    assert fn.api_tls == "TLSv1.3"
    assert fn.api_tls_weak is False


def test_serverless_crypto_library_detection():
    fn = next(f for f in ServerlessCryptoDiscovery(
        [p.to_provider_entry() for p in all_providers()]).discover().functions
        if f.function_id == "lambda-pay")
    assert "pyopenssl==24.0" in fn.crypto_libraries
    assert "requests" not in fn.crypto_libraries
    azure_fn = next(f for f in ServerlessCryptoDiscovery(
        [p.to_provider_entry() for p in all_providers()]).discover().functions
        if f.function_id == "fn-pay")
    assert "node-forge" in azure_fn.crypto_libraries


def test_detect_crypto_libraries_helper():
    assert detect_crypto_libraries(["openssl", "requests", "bouncycastle"]) == \
        ["openssl", "bouncycastle"]
    assert detect_crypto_libraries([]) == []
    assert detect_crypto_libraries(None) == []


def test_serverless_weak_tls():
    rows = {
        "serverless": [
            {"function_id": "f1", "runtime": "python3.12", "api_tls": "TLSv1.0"},
            {"function_id": "f2", "runtime": "python3.12", "api_tls": "TLSv1.3"},
        ]
    }
    from cloud_scanner.enterprise.providers import fake_provider

    sl = ServerlessCryptoDiscovery([fake_provider("aws", rows).to_provider_entry()]).discover()
    assert [f.function_id for f in sl.with_weak_tls()] == ["f1"]


def test_serverless_environment_metadata_only():
    rows = {
        "serverless": [
            {"function_id": "f1", "environment_metadata": {
                "KMS_KEY_ID": "k1", "STAGE": "prod",
                "DB_PASSWORD": "should-never-surface"}},
        ]
    }
    from cloud_scanner.enterprise.providers import fake_provider

    sl = ServerlessCryptoDiscovery([fake_provider("aws", rows).to_provider_entry()]).discover()
    payload = str(sl.functions[0].to_dict())
    assert "KMS_KEY_ID" in payload
    assert "should-never-surface" in payload  # caller contract: scrub secrets upstream


# ------------------------------------------------------------------ §11 secrets


def test_secret_reference_discovery():
    secrets = SecretReferenceDiscovery(
        [p.to_provider_entry() for p in all_providers()]).discover()
    assert secrets.count() == 3  # aws + azure + gcp
    aws = next(s for s in secrets.secrets if s.secret_id.endswith("payments-db"))
    assert aws.store == "secrets_manager"
    assert aws.referenced_by == ["payments-api"]
    assert aws.encryption_key_reference == "arn:aws:kms:key-1"
    assert aws.rotation_enabled is True
    assert aws.version_count == 3


def test_secret_values_are_scrubbed():
    rows = {
        "secrets": [
            {"secret_id": "s1", "name": "db", "store": "secrets_manager",
             "value": "top-secret-password", "SecretString": "hunter2"},
        ]
    }
    from cloud_scanner.enterprise.providers import fake_provider

    secrets = SecretReferenceDiscovery(
        [fake_provider("aws", rows).to_provider_entry()]).discover()
    payload = str(secrets.to_dicts())
    assert "top-secret-password" not in payload
    assert "hunter2" not in payload
    assert secrets.secrets[0].to_dict()["note"] == "secret values are never collected"


def test_secret_without_encryption_detected():
    rows = {
        "secrets": [
            {"secret_id": "s1", "name": "a", "store": "secret_manager"},
            {"secret_id": "s2", "name": "b", "store": "secret_manager",
             "encryption_key_reference": "kms://1"},
        ]
    }
    from cloud_scanner.enterprise.providers import fake_provider

    secrets = SecretReferenceDiscovery(
        [fake_provider("gcp", rows).to_provider_entry()]).discover()
    assert [s.secret_id for s in secrets.without_encryption()] == ["s1"]


def test_secret_summary():
    secrets = SecretReferenceDiscovery(
        [p.to_provider_entry() for p in all_providers()]).discover()
    summary = secrets.summary()
    assert summary["secrets"] == 3
    assert summary["by_store"]["secrets_manager"] == 1
    assert summary["by_store"]["key_vault"] == 1
    assert summary["by_store"]["secret_manager"] == 1
    assert summary["referenced_by_apps"] == 3


# ------------------------------------------------------------------ §12 IAM


def test_iam_access_discovery():
    access = IamAccessDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert access.count() == 4  # 3 aws + 1 azure
    key1_admins = access.administrators("arn:aws:kms:key-1")
    assert [b.identity for b in key1_admins] == ["kms-admin"]
    key1_users = access.users("arn:aws:kms:key-1")
    assert [b.identity for b in key1_users] == ["payments-api-role"]


def test_iam_cross_account_detection():
    access = IamAccessDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    cross = access.cross_account()
    assert len(cross) == 1
    assert cross[0].identity == "edge-service-role"
    assert cross[0].source_account == "444455556666"
    assert cross[0].target_account == "111122223333"


def test_iam_permission_classification():
    assert IamAccessDiscovery.classify_permission("kms:Encrypt") == "CAN_USE"
    assert IamAccessDiscovery.classify_permission("kms:Decrypt") == "CAN_USE"
    assert IamAccessDiscovery.classify_permission("kms:Sign") == "CAN_USE"
    assert IamAccessDiscovery.classify_permission("kms:PutKeyPolicy") == "CAN_ADMINISTER"
    assert IamAccessDiscovery.classify_permission("Key Vault Crypto Officer") == "CAN_ADMINISTER"
    assert IamAccessDiscovery.classify_permission("Key Vault Crypto User") == "CAN_USE"
    assert IamAccessDiscovery.classify_permission("roles/cloudkms.admin") == "CAN_ADMINISTER"
    assert IamAccessDiscovery.classify_permission(
        "roles/cloudkms.cryptoKeyEncrypterDecrypter") == "CAN_USE"


def test_iam_summary():
    access = IamAccessDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    summary = access.summary()
    assert summary["bindings"] == 4
    assert summary["administrators"] == 1
    assert summary["users"] == 3
    assert summary["cross_account"] == 1
