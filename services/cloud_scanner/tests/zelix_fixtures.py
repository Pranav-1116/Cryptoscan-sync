"""Shared fake multi-cloud estate for ZELNX engine tests.

A realistic bank-like estate: AWS org with 2 accounts, Azure tenant with 1
subscription, GCP org with 2 projects — plus keys, certificates, CAs,
storage/DB encryption, TLS endpoints, clusters, serverless functions,
secrets, IAM bindings and cross-cloud relationships.  No SDKs, no mocks —
plain dicts through :func:`fake_provider`.
"""

from __future__ import annotations

from cloud_scanner.enterprise.providers import ProviderAdapter, fake_provider

AWS_ACCOUNTS = [
    {"account_id": "111122223333", "name": "prod-core", "org_path": ["Payments"],
     "status": "ACTIVE", "email": "core@example.com"},
    {"account_id": "444455556666", "name": "prod-edge", "org_path": ["Payments"],
     "status": "ACTIVE"},
]
AZURE_ACCOUNTS = [
    {"account_id": "sub-aaa", "name": "payments-sub", "org_path": ["Payments"],
     "status": "ACTIVE"},
]
GCP_ACCOUNTS = [
    {"account_id": "proj-core", "name": "core-banking", "org_path": ["Payments"],
     "status": "ACTIVE"},
    {"account_id": "proj-edge", "name": "edge-services", "org_path": ["Payments"],
     "status": "ACTIVE"},
]


def _aws_regions(account):
    return [
        {"name": "us-east-1", "zones": ["us-east-1a", "us-east-1b"], "resource_count": 3},
        {"name": "eu-west-1", "zones": ["eu-west-1a"], "resource_count": 1},
    ]


def _azure_regions(account):
    return [
        {"name": "westeurope", "zones": ["1", "2"], "resource_count": 2},
    ]


def _gcp_regions(account):
    return [
        {"name": "us-central1", "zones": ["us-central1-a", "us-central1-b"],
         "resource_count": 2},
    ]


AWS_ROWS = {
    "workloads": [
        {"workload_id": "i-0001", "account": "111122223333", "region": "us-east-1",
         "environment": "prod", "network": "vpc-core", "application": "payments-api",
         "owner": "payments-team", "runtime": "java17", "os": "amazon-linux-2",
         "compute_type": "ec2",
         "crypto_usage": ["TLS1.3", "AES-256"], "certificate_usage": ["arn:aws:acm:cert-1"],
         "key_dependencies": ["arn:aws:kms:key-1"]},
        {"workload_id": "lambda-pay", "account": "111122223333", "region": "us-east-1",
         "environment": "prod", "application": "payments-api", "owner": "payments-team",
         "runtime": "python3.12", "compute_type": "lambda",
         "key_dependencies": ["arn:aws:kms:key-1"]},
        {"workload_id": "eks-bank", "account": "444455556666", "region": "eu-west-1",
         "environment": "prod", "network": "vpc-edge", "runtime": "containerd",
         "compute_type": "eks", "container": "banking-agent:1.2.0",
         "key_dependencies": ["arn:aws:kms:key-2"]},
    ],
    "keys": [
        {"key_id": "arn:aws:kms:key-1", "name": "payments-master", "account": "111122223333",
         "region": "us-east-1", "key_spec": "SYMMETRIC_DEFAULT", "key_state": "Enabled",
         "key_manager": "CUSTOMER_MANAGED", "rotation_enabled": True,
         "origin": "AWS_KMS", "multi_region": True, "aliases": ["alias/payments-master"]},
        {"key_id": "arn:aws:kms:key-2", "name": "edge-signing", "account": "444455556666",
         "region": "eu-west-1", "key_spec": "RSA_2048", "key_state": "Enabled",
         "key_manager": "CUSTOMER_MANAGED", "rotation_enabled": False,
         "origin": "AWS_KMS", "key_usage": "SIGN_VERIFY", "purpose": "SIGNING"},
        {"key_id": "arn:aws:kms:key-aws", "name": "aws/s3", "account": "111122223333",
         "key_spec": "SYMMETRIC_DEFAULT", "key_state": "Enabled",
         "key_manager": "AWS", "rotation_enabled": True},
    ],
    "certificates": [
        {"certificate_id": "arn:aws:acm:cert-1", "account": "111122223333",
         "region": "us-east-1", "domain": "api.bank.example", "serial": "AA11",
         "valid_to": "2030-01-01T00:00:00Z", "signature_algorithm": "SHA256WithRSA",
         "public_key_algorithm": "RSA", "key_size": 2048, "status": "ISSUED",
         "imported": False, "used_by": ["payments-api"], "dependencies": ["arn:aws:elb:lb-1"],
         "ca_id": "arn:aws:acm-pca:ca-root"},
        {"certificate_id": "arn:aws:acm:cert-exp", "account": "111122223333",
         "domain": "expiring.bank.example", "serial": "BB22",
         "valid_to": "2026-09-10T00:00:00Z", "signature_algorithm": "SHA1WithRSA",
         "public_key_algorithm": "RSA", "key_size": 1024, "status": "ISSUED",
         "ca_id": "arn:aws:acm-pca:ca-root"},
    ],
    "cas": [
        {"ca_id": "arn:aws:acm-pca:ca-root", "name": "bank-root", "ca_type": "ROOT",
         "signature_algorithm": "SHA384WithRSA", "public_key_algorithm": "RSA",
         "key_size": 4096, "expires_at": "2035-01-01T00:00:00Z", "templates": ["server-tls"]},
        {"ca_id": "arn:aws:acm-pca:ca-sub", "name": "bank-subordinate",
         "ca_type": "SUBORDINATE", "parent_id": "arn:aws:acm-pca:ca-root",
         "signature_algorithm": "SHA256WithRSA", "public_key_algorithm": "RSA",
         "key_size": 2048, "expires_at": "2030-01-01T00:00:00Z"},
    ],
    "encryption": [
        {"resource_id": "s3-payments", "account": "111122223333", "region": "us-east-1",
         "resource_type": "s3", "encrypted": True, "customer_managed": True,
         "key_reference": "arn:aws:kms:key-1", "encryption_algorithm": "aws:kms",
         "in_transit": "TLS_ENABLED"},
        {"resource_id": "rds-payments", "account": "111122223333", "region": "us-east-1",
         "resource_type": "rds", "encrypted": False, "in_transit": "TLS_ENABLED"},
    ],
    "tls_profiles": [
        {"profile_id": "lb-1", "account": "111122223333", "service": "elbv2",
         "tls_versions": ["TLSv1.3", "TLSv1.2"], "certificate_id": "arn:aws:acm:cert-1"},
        {"profile_id": "cf-1", "account": "111122223333", "service": "cloudfront",
         "tls_versions": ["TLSv1.0"], "weak": True},
    ],
    "ipsec_profiles": [
        {"profile_id": "vpn-1", "account": "111122223333", "service": "vpn",
         "ike_version": "IKEv2", "encryption": ["AES256"], "integrity": ["SHA256"],
         "dh_groups": [14], "pfs": True},
        {"profile_id": "vpn-2", "account": "444455556666", "service": "vpn",
         "ike_version": "IKEv1", "encryption": ["3DES"], "integrity": ["SHA1"],
         "dh_groups": [2], "pfs": False},
    ],
    "tunnels": [
        {"source": "vpc-core", "target": "vpn-1", "kind": "VPN_TUNNEL",
         "account": "111122223333"},
        {"source": "vpc-edge", "target": "vpn-2", "kind": "VPN_TUNNEL",
         "account": "444455556666"},
    ],
    "tls_endpoints": [
        {"endpoint": "api.bank.example", "account": "111122223333", "region": "us-east-1",
         "service": "elbv2", "application": "payments-api", "tls_version": "TLSv1.3",
         "key_exchange": "ECDHE", "public_key_size": 2048, "certificate_id": "arn:aws:acm:cert-1"},
        {"endpoint": "legacy.bank.example", "account": "111122223333",
         "service": "cloudfront", "tls_version": "TLSv1.0", "key_exchange": "ECDHE",
         "public_key_size": 1024, "certificate_id": "arn:aws:acm:cert-exp"},
    ],
    "clusters": [
        {"cluster_id": "eks-bank", "account": "444455556666", "region": "eu-west-1",
         "api_tls_version": "TLSv1.3", "secrets_encryption": "KMS_ENCRYPTED",
         "secrets_key_reference": "arn:aws:kms:key-2", "etcd_encryption": "ENABLED",
         "nodes": ["node-1", "node-2"], "namespaces": ["payments", "infra"],
         "mesh": "ISTIO", "mesh_mtls": "STRICT",
         "ingress_tls": [{"host": "bank.example", "certificate_id": "arn:aws:acm:cert-1",
                          "secret_name": "tls-bank", "issuer": "ca-issuer"}],
         "workloads": [{"workload": "banking-agent", "namespace": "payments",
                        "crypto_libraries": ["openssl"], "image": "banking-agent:1.2.0",
                        "image_digest": "sha256:abc", "identity": "iam-role-bank",
                        "key_references": ["arn:aws:kms:key-2"]}]},
    ],
    "serverless": [
        {"function_id": "lambda-pay", "account": "111122223333", "region": "us-east-1",
         "runtime": "python3.12", "dependencies": ["pyopenssl==24.0", "requests"],
         "key_references": ["arn:aws:kms:key-1"],
         "certificate_references": ["arn:aws:acm:cert-1"], "api_tls": "TLSv1.3"},
    ],
    "secrets": [
        {"secret_id": "arn:aws:secretsmanager:payments-db", "account": "111122223333",
         "region": "us-east-1", "store": "secrets_manager", "name": "payments-db",
         "referenced_by": ["payments-api"], "encryption_key_reference": "arn:aws:kms:key-1",
         "rotation_enabled": True, "version_count": 3},
    ],
    "access": [
        {"identity": "payments-api-role", "key_id": "arn:aws:kms:key-1",
         "permission": "kms:Encrypt,kms:Decrypt", "source_account": "111122223333",
         "target_account": "111122223333", "granted_via": "iam_policy"},
        {"identity": "kms-admin", "key_id": "arn:aws:kms:key-1",
         "permission": "kms:PutKeyPolicy", "source_account": "111122223333",
         "target_account": "111122223333", "granted_via": "key_policy"},
        {"identity": "edge-service-role", "key_id": "arn:aws:kms:key-2",
         "permission": "kms:Sign", "source_account": "444455556666",
         "target_account": "111122223333", "granted_via": "iam_policy"},
    ],
    "cross_cloud": [
        {"source": "payments-api", "target": "azure-apis", "kind": "API_RELATIONSHIP",
         "source_provider": "aws", "target_provider": "azure",
         "source_account": "111122223333", "target_account": "sub-aaa",
         "crypto_dependencies": ["TLS1.3"]},
        {"source": "azure-apis", "target": "gcp-billing", "kind": "API_RELATIONSHIP",
         "source_provider": "azure", "target_provider": "gcp",
         "source_account": "sub-aaa", "target_account": "proj-core",
         "crypto_dependencies": ["TLS1.3", "mTLS"]},
    ],
}

AZURE_ROWS = {
    "workloads": [
        {"workload_id": "vm-pay", "account": "sub-aaa", "region": "westeurope",
         "environment": "prod", "network": "vnet-payments", "application": "payments-api",
         "owner": "payments-team", "runtime": "dotnet8", "os": "ubuntu-22.04",
         "compute_type": "vm", "key_dependencies": ["keyvault://kv-payments/key-1"]},
    ],
    "keys": [
        {"key_id": "keyvault://kv-payments/key-1", "name": "payments-key",
         "account": "sub-aaa", "key_spec": "RSA-HSM 2048", "key_state": "Enabled",
         "key_usage": "encrypt,decrypt,wrapKey", "key_manager": "CUSTOMER_MANAGED",
         "rotation_enabled": True, "hsm_backed": True, "expiration": "2032-01-01T00:00:00Z"},
    ],
    "certificates": [
        {"certificate_id": "keyvault://kv-payments/cert-api", "account": "sub-aaa",
         "domain": "api.az.bank.example", "valid_to": "2029-06-01T00:00:00Z",
         "signature_algorithm": "ES256", "public_key_algorithm": "ECDSA",
         "curve": "P-256", "stored_in": "keyvault://kv-payments", "status": "ENABLED"},
    ],
    "encryption": [
        {"resource_id": "blob-payments", "account": "sub-aaa", "resource_type": "blob",
         "encrypted": True, "customer_managed": True,
         "key_reference": "keyvault://kv-payments/key-1", "in_transit": "TLS_ENABLED"},
    ],
    "tls_profiles": [
        {"profile_id": "agw-1", "account": "sub-aaa", "service": "app_gateway",
         "tls_versions": ["TLSv1.2"], "certificate_id": "keyvault://kv-payments/cert-api"},
    ],
    "tls_endpoints": [
        {"endpoint": "api.az.bank.example", "account": "sub-aaa", "service": "app_gateway",
         "application": "payments-api", "tls_version": "TLSv1.2", "key_exchange": "ECDHE",
         "certificate_id": "keyvault://kv-payments/cert-api", "curve": "P-256"},
    ],
    "clusters": [
        {"cluster_id": "aks-payments", "account": "sub-aaa", "region": "westeurope",
         "api_tls_version": "TLSv1.2", "secrets_encryption": "KMS_ENCRYPTED",
         "secrets_key_reference": "keyvault://kv-payments/key-1",
         "etcd_encryption": "ENABLED", "mesh": "LINKERD", "mesh_mtls": "PERMISSIVE",
         "workloads": [{"workload": "svc-a", "namespace": "payments",
                        "crypto_libraries": ["bouncycastle"], "mtls": True}]},
    ],
    "serverless": [
        {"function_id": "fn-pay", "account": "sub-aaa", "region": "westeurope",
         "runtime": "nodejs20", "dependencies": ["node-forge"], "api_tls": "TLSv1.3"},
    ],
    "secrets": [
        {"secret_id": "keyvault://kv-payments/conn-str", "account": "sub-aaa",
         "store": "key_vault", "name": "conn-str", "referenced_by": ["fn-pay"],
         "encryption_key_reference": "keyvault://kv-payments/key-1"},
    ],
    "access": [
        {"identity": "fn-pay-mi", "key_id": "keyvault://kv-payments/key-1",
         "permission": "Key Vault Crypto User", "source_account": "sub-aaa",
         "target_account": "sub-aaa", "granted_via": "iam_binding"},
    ],
}

GCP_ROWS = {
    "workloads": [
        {"workload_id": "gke-bank", "account": "proj-core", "region": "us-central1",
         "environment": "prod", "network": "vpc-bank", "application": "billing-svc",
         "runtime": "gvisor", "compute_type": "gke", "key_dependencies": ["gcp-kms://ring-1/key-1"]},
        {"workload_id": "run-edge", "account": "proj-edge", "region": "us-central1",
         "environment": "prod", "application": "edge-svc", "runtime": "go1.22",
         "compute_type": "cloud_run", "key_dependencies": ["gcp-kms://ring-1/key-2"]},
    ],
    "keys": [
        {"key_id": "gcp-kms://ring-1/key-1", "name": "billing-key",
         "account": "proj-core", "key_spec": "GOOGLE_SYMMETRIC_ENCRYPTION",
         "key_state": "ENABLED", "purpose": "ENCRYPT_DECRYPT",
         "rotation_period_days": 90, "protection_level": "HSM", "hsm_backed": True,
         "dependencies": ["projects/proj-core/locations/us-central1/keyRings/ring-1"]},
        {"key_id": "gcp-kms://ring-1/key-2", "name": "edge-key",
         "account": "proj-edge", "key_spec": "EC_SIGN_P256_SHA256",
         "key_state": "ENABLED", "purpose": "ASYMMETRIC_SIGN",
         "rotation_enabled": False},
    ],
    "certificates": [
        {"certificate_id": "cert-mgr-1", "account": "proj-core",
         "domain": "billing.gcp.bank.example", "valid_to": "2028-01-01T00:00:00Z",
         "signature_algorithm": "SHA256WithRSA", "public_key_algorithm": "RSA",
         "key_size": 2048, "status": "ACTIVE", "ca_id": "ca-service://ca-bank"},
    ],
    "cas": [
        {"ca_id": "ca-service://ca-bank", "name": "gcp-bank-ca", "ca_type": "ISSUING",
         "signature_algorithm": "SHA256WithRSA", "public_key_algorithm": "RSA",
         "key_size": 2048, "expires_at": "2031-01-01T00:00:00Z",
         "parent_id": "ca-service://ca-root"},
        {"ca_id": "ca-service://ca-root", "name": "gcp-bank-root", "ca_type": "ROOT",
         "signature_algorithm": "SHA384WithRSA", "public_key_algorithm": "RSA",
         "key_size": 4096, "expires_at": "2036-01-01T00:00:00Z"},
    ],
    "encryption": [
        {"resource_id": "gcs-billing", "account": "proj-core", "resource_type": "gcs",
         "encrypted": True, "customer_managed": True,
         "key_reference": "gcp-kms://ring-1/key-1", "in_transit": "TLS_ENABLED"},
    ],
    "tls_endpoints": [
        {"endpoint": "billing.gcp.bank.example", "account": "proj-core",
         "service": "load_balancer", "application": "billing-svc", "tls_version": "TLSv1.3",
         "key_exchange": "X25519", "certificate_id": "cert-mgr-1"},
    ],
    "clusters": [
        {"cluster_id": "gke-bank", "account": "proj-core", "region": "us-central1",
         "api_tls_version": "TLSv1.3", "secrets_encryption": "KMS_ENCRYPTED",
         "secrets_key_reference": "gcp-kms://ring-1/key-1",
         "etcd_encryption": "ENABLED", "mesh": "ISTIO", "mesh_mtls": "STRICT"},
    ],
    "secrets": [
        {"secret_id": "gcp-secret://billing-token", "account": "proj-core",
         "store": "secret_manager", "name": "billing-token",
         "referenced_by": ["billing-svc"], "encryption_key_reference": "gcp-kms://ring-1/key-1"},
    ],
}


def all_providers() -> list[ProviderAdapter]:
    return [
        fake_provider("aws", AWS_ROWS, accounts=AWS_ACCOUNTS, region_rows=_aws_regions),
        fake_provider("azure", AZURE_ROWS, accounts=AZURE_ACCOUNTS, region_rows=_azure_regions),
        fake_provider("gcp", GCP_ROWS, accounts=GCP_ACCOUNTS, region_rows=_gcp_regions),
    ]
