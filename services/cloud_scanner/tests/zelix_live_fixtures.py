"""Shared fixtures for ZELNX Live Cloud Intelligence Engine tests.

A realistic multi-cloud estate used to feed the live engine: raw AWS /
Azure / GCP payloads for every source family (events, audit, API state,
reconciliation), plus resolvers (dependencies, cert consumers, network
paths, workload identity, cross-cloud impact) wired to the canonical
ZELNX fixture estate.
"""

from __future__ import annotations

from typing import Any

from cloud_scanner.enterprise.live.connectors import (
    ProviderConnector,
    aws_connector,
    azure_connector,
    gcp_connector,
)
from cloud_scanner.enterprise.live.engine import LiveCloudEngine
from cloud_scanner.enterprise.live.event_schema import CloudEvent

# --------------------------------------------------------------------- raw AWS

AWS_KEY = "arn:aws:kms:us-east-1:111122223333:key/key-prod-1"
AWS_KEY2 = "arn:aws:kms:us-east-1:111122223333:key/key-prod-2"
AWS_CERT = "arn:aws:acm:us-east-1:111122223333:certificate/cert-api-1"
AWS_LB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/lb-api"
AZURE_CERT = "/subscriptions/sub-aaa/resourceGroups/rg-pay/providers/Microsoft.KeyVault/vaults/vault-pay/certificates/pay-cert"
AZURE_KEY = "/subscriptions/sub-aaa/resourceGroups/rg-pay/providers/Microsoft.KeyVault/vaults/vault-pay/keys/pay-key"
GCP_KEY = "projects/proj-core/locations/global/keyRings/kr-pay/cryptoKeys/gk-pay"
GCP_CERT = "projects/proj-core/locations/global/certificates/gcm-pay"
ROOT_CA = "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/root-ca-1"


def aws_events() -> list[dict[str, Any]]:
    return [
        {"event_id": "aws-ev-001", "provider": "aws", "event_name": "kms:PutKeyPolicy",
         "resource_id": AWS_KEY, "resource_type": "AWS::KMS::Key",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:59:00Z", "userIdentity": "arn:aws:iam::111122223333:user/alice",
         "kms_detail": {"policy_version": "v3"}},
        {"event_id": "aws-ev-002", "provider": "aws", "event_name": "acm:ImportCertificate",
         "resource_id": AWS_CERT, "resource_type": "AWS::ACM::Certificate",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:58:00Z",
         "algorithm": "RSA-2048", "public_internet_exposed": True,
         "criticality": "HIGH"},
        {"event_id": "aws-ev-003", "provider": "aws",
         "event_name": "elbv2:ModifyListener",
         "resource_id": AWS_LB, "resource_type": "AWS::ElasticLoadBalancingV2::Listener",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:57:00Z",
         "depends_on": AWS_CERT},
        {"event_id": "aws-ev-004", "provider": "aws", "event_name": "ec2:CreateRoute",
         "resource_id": "rtb-0abc", "resource_type": "AWS::EC2::Route",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:56:00Z"},
        {"event_id": "aws-ev-005", "provider": "aws", "event_name": "eks:CreateCluster",
         "resource_id": "eks-prod-1", "resource_type": "AWS::EKS::Cluster",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:55:00Z",
         "cluster_id": "eks-prod-1", "namespace": "payments"},
        {"event_id": "aws-ev-006", "provider": "aws", "event_name": "lambda:UpdateFunctionConfiguration",
         "resource_id": "lambda-pay", "resource_type": "AWS::Lambda::Function",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:54:00Z",
         "runtime": "nodejs20", "crypto_libraries": ["node-forge"], "key_references": [AWS_KEY]},
    ]


def aws_audit() -> list[dict[str, Any]]:
    return [
        {"event_id": "aws-aud-001", "provider": "aws", "event_name": "kms:ScheduleKeyDeletion",
         "resource_id": AWS_KEY2, "resource_type": "AWS::KMS::Key",
         "awsRegion": "eu-west-1", "account": "111122223333",
         "timestamp": "2026-05-01T08:00:00Z"},
    ]


def aws_api_state() -> list[dict[str, Any]]:
    return [
        {"event_id": "aws-api-001", "provider": "aws", "event_name": "KMS.DescribeKey",
         "resource_id": AWS_KEY, "resource_type": "AWS::KMS::Key",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:50:00Z",
         "state": {"rotation_enabled": True, "encryption_enabled": True,
                   "algorithm": "SYMMETRIC_DEFAULT"}},
    ]


def aws_reconcile() -> list[dict[str, Any]]:
    return [
        {"event_id": "aws-rec-001", "provider": "aws", "event_name": "ReconcileScan",
         "resource_id": AWS_CERT, "resource_type": "AWS::ACM::Certificate",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-05-01T09:00:00Z", "state": {"status": "ISSUED"}},
    ]


# -------------------------------------------------------------------- raw Azure

def azure_events() -> list[dict[str, Any]]:
    return [
        {"event_id": "az-ev-001", "provider": "azure",
         "resource_type": "Microsoft.KeyVault/vaults/certificates",
         "resourceId": AZURE_CERT, "subscriptionId": "sub-aaa",
         "location": "westeurope", "timestamp": "2026-05-01T09:53:00Z",
         "operation": "Microsoft.KeyVault/vaults/certificates/write",
         "certificate_algorithm": "EC-P256", "criticality": "HIGH"},
        {"event_id": "az-ev-002", "provider": "azure",
         "resource_type": "Microsoft.KeyVault/vaults/keys",
         "resourceId": AZURE_KEY, "subscriptionId": "sub-aaa",
         "location": "westeurope", "timestamp": "2026-05-01T09:52:00Z"},
        {"event_id": "az-ev-003", "provider": "azure",
         "resource_type": "Microsoft.Network/vpnGateways",
         "resourceId": "/subscriptions/sub-aaa/resourceGroups/rg-pay/providers/Microsoft.Network/vpnGateways/vpn-1",
         "subscriptionId": "sub-aaa", "location": "westeurope",
         "timestamp": "2026-05-01T09:51:00Z"},
        {"event_id": "az-ev-004", "provider": "azure",
         "resource_type": "Microsoft.Web/sites",
         "resourceId": "/subscriptions/sub-aaa/resourceGroups/rg-pay/providers/Microsoft.Web/sites/fn-pay",
         "subscriptionId": "sub-aaa", "location": "westeurope",
         "timestamp": "2026-05-01T09:50:00Z", "runtime": "dotnet8"},
    ]


def azure_audit() -> list[dict[str, Any]]:
    return [
        {"event_id": "az-aud-001", "provider": "azure",
         "resource_type": "Microsoft.KeyVault/vaults/certificates",
         "resourceId": AZURE_CERT, "subscriptionId": "sub-aaa",
         "location": "westeurope", "timestamp": "2026-05-01T08:30:00Z",
         "operation": "Microsoft.KeyVault/vaults/certificates/update/action"},
    ]


# ---------------------------------------------------------------------- raw GCP

def gcp_events() -> list[dict[str, Any]]:
    return [
        {"event_id": "gcp-ev-001", "provider": "gcp",
         "operation": "cloudkms.CryptoKey.Rotate",
         "resource_id": GCP_KEY, "resource_type": "CloudKMS:CryptoKey",
         "location": "global", "project": "proj-core",
         "timestamp": "2026-05-01T09:49:00Z",
         "protection_level": "HSM"},
        {"event_id": "gcp-ev-002", "provider": "gcp",
         "operation": "certificatemanager.Certificate.Create",
         "resource_id": GCP_CERT, "resource_type": "CertificateManager:Certificate",
         "location": "global", "project": "proj-core",
         "timestamp": "2026-05-01T09:48:00Z",
         "algorithm": "RSA-3072"},
        {"event_id": "gcp-ev-003", "provider": "gcp",
         "operation": "run.googleapis.com.services.create",
         "resource_id": "projects/proj-core/locations/us-central1/services/analytics-svc",
         "resource_type": "CloudRun:Service", "location": "us-central1",
         "project": "proj-core", "timestamp": "2026-05-01T09:47:00Z"},
    ]


def gcp_audit() -> list[dict[str, Any]]:
    return [
        {"event_id": "gcp-aud-001", "provider": "gcp",
         "operation": "compute.googleapis.com.routes.insert",
         "resource_id": "projects/proj-edge/global/routes/route-gcp",
         "resource_type": "Compute:Route", "location": "global",
         "project": "proj-edge", "timestamp": "2026-05-01T08:45:00Z"},
    ]


# ------------------------------------------------------------------- resolvers

def live_resolvers() -> dict[str, Any]:
    """Resolvers wired to the canonical fixture estate."""
    def find_dependencies(resource_id: str) -> list[dict[str, Any]]:
        table = {
            AWS_KEY: [{"resource": "payments-api", "kind": "application"},
                      {"resource": "dataset-payments", "kind": "dataset"},
                      {"resource": "lambda-pay", "kind": "application"}],
            AZURE_KEY: [{"resource": "fn-pay", "kind": "application"},
                        {"resource": "db-pay", "kind": "dataset"}],
            GCP_KEY: [{"resource": "analytics-svc", "kind": "application"},
                      {"resource": "bigquery-pay", "kind": "dataset"}],
        }
        return table.get(resource_id, [])

    def find_key_access(resource_id: str) -> list[dict[str, Any]]:
        table = {
            AWS_KEY: [{"identity": "svc-payments", "effect": "Allow"},
                      {"identity": "role-billing", "effect": "Allow"}],
            AZURE_KEY: [{"identity": "sp-fn-pay", "effect": "Allow"}],
            GCP_KEY: [{"identity": "sa-analytics@proj-core", "effect": "Allow"}],
        }
        return table.get(resource_id, [])

    def find_cert_consumers(resource_id: str) -> list[dict[str, Any]]:
        table = {
            AWS_CERT: [{"resource": "lb-api", "kind": "load_balancer"},
                       {"resource": "payments-api", "kind": "application"}],
            AZURE_CERT: [{"resource": "appgw-pay", "kind": "load_balancer"},
                         {"resource": "fn-pay", "kind": "application"}],
            GCP_CERT: [{"resource": "lb-gcp", "kind": "load_balancer"}],
        }
        return table.get(resource_id, [])

    def find_network_paths(resource_id: str) -> list[list[str]]:
        table = {
            AWS_LB: [["lb-api", "TLS1.2", AWS_CERT], ["payments-api", "TLS1.3", AWS_CERT]],
            AZURE_CERT: [["appgw-pay", "TLS1.2", "client-browser"]],
        }
        return table.get(resource_id, [])

    def resolve_workload_identity(resource_id: str) -> str:
        table = {"eks-prod-1": "workload:payments-svc", "lambda-pay": "workload:fn-pay"}
        return table.get(resource_id, "")

    def find_workload_crypto(resource_id: str) -> list[str]:
        table = {"eks-prod-1": [AWS_KEY, AWS_CERT]}
        return table.get(resource_id, [])

    def analyze_serverless(event: CloudEvent) -> dict[str, Any]:
        meta = event.provider_metadata
        return {
            "runtime": meta.get("runtime") or "",
            "crypto_libraries": meta.get("crypto_libraries") or [],
            "key_references": meta.get("key_references") or [],
        }

    def detect_algorithm(event: CloudEvent) -> str:
        meta = event.provider_metadata
        return str(meta.get("algorithm") or meta.get("certificate_algorithm") or "") or ""

    def find_cross_cloud_impact(resource_id: str) -> dict[str, list[str]]:
        # AWS cert → Azure + GCP consumers (§15)
        table = {
            AWS_CERT: {"aws": ["payments-api", "lb-api"],
                       "azure": [AZURE_CERT, "appgw-pay"],
                       "gcp": [GCP_CERT]},
            AZURE_CERT: {"azure": ["appgw-pay", "fn-pay"]},
            GCP_KEY: {"gcp": ["analytics-svc"], "aws": ["payments-api"]},
        }
        return table.get(resource_id, {})

    return {
        "find_dependencies": find_dependencies,
        "find_key_access": find_key_access,
        "find_cert_consumers": find_cert_consumers,
        "find_network_paths": find_network_paths,
        "resolve_workload_identity": resolve_workload_identity,
        "find_workload_crypto": find_workload_crypto,
        "analyze_serverless": analyze_serverless,
        "detect_algorithm": detect_algorithm,
        "find_cross_cloud_impact": find_cross_cloud_impact,
    }


def all_live_connectors() -> list[ProviderConnector]:
    """One connector per provider with every source family populated."""
    return [
        aws_connector(event_source=aws_events, audit_source=aws_audit,
                      api_state_source=aws_api_state, reconcile_source=aws_reconcile,
                      organization_id="org-zelnx"),
        azure_connector(event_source=azure_events, audit_source=azure_audit,
                        organization_id="org-zelnx"),
        gcp_connector(event_source=gcp_events, audit_source=gcp_audit,
                      organization_id="org-zelnx"),
    ]


def make_live_engine(*, connectors: list[ProviderConnector] | None = None,
                     clock=None, **resolver_overrides: Any) -> LiveCloudEngine:
    """Build a fully-wired live engine (injectable clock + overrides)."""
    resolvers = live_resolvers()
    resolvers.update(resolver_overrides)
    return LiveCloudEngine(
        connectors=list(connectors or all_live_connectors()),
        clock=clock or (lambda: "2026-05-01T10:00:00Z"),
        resolve_dependencies=resolvers["find_dependencies"],
        find_key_access=resolvers["find_key_access"],
        find_cert_consumers=resolvers["find_cert_consumers"],
        find_network_paths=resolvers["find_network_paths"],
        resolve_workload_identity=resolvers["resolve_workload_identity"],
        find_workload_crypto=resolvers["find_workload_crypto"],
        analyze_serverless=resolvers["analyze_serverless"],
        detect_algorithm=resolvers["detect_algorithm"],
        find_cross_cloud_impact=resolvers["find_cross_cloud_impact"],
    )
