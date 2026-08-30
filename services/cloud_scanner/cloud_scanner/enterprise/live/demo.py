"""ZELNX Live Cloud Intelligence Engine — CLI demo wiring.

Sample multi-cloud event streams used when the live CLI runs without a
real cloud connection (``--zelix-live``).  Read-only: no key material or
secret values are ever represented here.
"""

from __future__ import annotations

from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent

AWS_KEY = "arn:aws:kms:us-east-1:111122223333:key/key-prod-1"
AWS_CERT = "arn:aws:acm:us-east-1:111122223333:certificate/cert-api-1"
AZURE_CERT = ("/subscriptions/sub-aaa/resourceGroups/rg-pay/providers/"
              "Microsoft.KeyVault/vaults/vault-pay/certificates/pay-cert")
GCP_KEY = "projects/proj-core/locations/global/keyRings/kr-pay/cryptoKeys/gk-pay"


def demo_raw_events() -> list[dict[str, Any]]:
    """Raw provider payloads covering AWS / Azure / GCP (§3–§5)."""
    return [
        {"event_id": "demo-aws-1", "provider": "aws", "event_name": "kms:PutKeyPolicy",
         "resource_id": AWS_KEY, "resource_type": "AWS::KMS::Key",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-08-30T09:59:00Z", "userIdentity": "demo:ops"},
        {"event_id": "demo-aws-2", "provider": "aws", "event_name": "acm:ImportCertificate",
         "resource_id": AWS_CERT, "resource_type": "AWS::ACM::Certificate",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-08-30T09:58:00Z", "algorithm": "RSA-2048",
         "public_internet_exposed": True, "criticality": "HIGH"},
        {"event_id": "demo-aws-3", "provider": "aws",
         "event_name": "elbv2:ModifyListener",
         "resource_id": "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/lb-api",
         "resource_type": "AWS::ElasticLoadBalancingV2::Listener",
         "awsRegion": "us-east-1", "account": "111122223333",
         "timestamp": "2026-08-30T09:57:00Z", "depends_on": AWS_CERT},
        {"event_id": "demo-az-1", "provider": "azure",
         "resource_type": "Microsoft.KeyVault/vaults/certificates",
         "resourceId": AZURE_CERT, "subscriptionId": "sub-aaa",
         "location": "westeurope", "timestamp": "2026-08-30T09:53:00Z",
         "operation": "Microsoft.KeyVault/vaults/certificates/write",
         "certificate_algorithm": "EC-P256", "criticality": "HIGH"},
        {"event_id": "demo-gcp-1", "provider": "gcp",
         "operation": "cloudkms.CryptoKey.Rotate",
         "resource_id": GCP_KEY, "resource_type": "CloudKMS:CryptoKey",
         "location": "global", "project": "proj-core",
         "timestamp": "2026-08-30T09:49:00Z", "protection_level": "HSM"},
        {"event_id": "demo-gcp-2", "provider": "gcp",
         "operation": "certificatemanager.Certificate.Create",
         "resource_id": "projects/proj-core/locations/global/certificates/gcm-pay",
         "resource_type": "CertificateManager:Certificate",
         "location": "global", "project": "proj-core",
         "timestamp": "2026-08-30T09:48:00Z", "algorithm": "RSA-3072"},
    ]


def demo_resolvers() -> dict[str, Any]:
    """Small resolvers so the demo shows blast radius + PQC output."""
    def find_dependencies(resource_id: str) -> list[dict[str, Any]]:
        table = {
            AWS_KEY: [{"resource": "payments-api", "kind": "application"},
                      {"resource": "dataset-payments", "kind": "dataset"}],
            GCP_KEY: [{"resource": "analytics-svc", "kind": "application"}],
        }
        return table.get(resource_id, [])

    def find_cert_consumers(resource_id: str) -> list[dict[str, Any]]:
        table = {
            AWS_CERT: [{"resource": "lb-api", "kind": "load_balancer"},
                       {"resource": "payments-api", "kind": "application"}],
            AZURE_CERT: [{"resource": "appgw-pay", "kind": "load_balancer"}],
        }
        return table.get(resource_id, [])

    def find_cross_cloud_impact(resource_id: str) -> dict[str, list[str]]:
        table = {
            AWS_CERT: {"aws": ["payments-api", "lb-api"],
                       "azure": [AZURE_CERT, "appgw-pay"]},
        }
        return table.get(resource_id, {})

    def detect_algorithm(event: CloudEvent) -> str:
        meta = event.provider_metadata
        return str(meta.get("algorithm") or meta.get("certificate_algorithm") or "") or ""

    return {
        "find_dependencies": find_dependencies,
        "find_cert_consumers": find_cert_consumers,
        "find_cross_cloud_impact": find_cross_cloud_impact,
        "detect_algorithm": detect_algorithm,
    }
