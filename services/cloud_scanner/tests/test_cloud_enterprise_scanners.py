"""Enterprise crypto scanners added for full-part coverage: DNS signing
(Route53/DNS/Cloud DNS), registry encryption (ECR/ACR), storage encryption
(EFS), HSM custody (CloudHSM/Managed HSM), VPN IPsec policies (Azure), app
transport (App Service), and cache/service CMEK (Memorystore/Cloud Run).

Same injected-client style as the other live-scanner tests: plain objects /
dicts, no SDKs, no mocks of the code under test.
"""

from __future__ import annotations

from types import SimpleNamespace

from cloud_scanner.aws.scanners import (
    scan_cloudhsm,
    scan_ecr,
    scan_efs,
    scan_route53,
)
from cloud_scanner.azure.scanners import (
    scan_acr,
    scan_app_service,
    scan_dns,
    scan_managed_hsm,
    scan_vpn_gateway,
)
from cloud_scanner.gcp.scanners import (
    scan_cloud_dns,
    scan_cloud_run,
    scan_memorystore,
)

# ------------------------------------------------------------------ AWS


class _Route53:
    def list_hosted_zones(self):
        return {
            "HostedZones": [
                {"Id": "/hostedzone/Z1", "Name": "signed.example.", "Config": {"PrivateZone": False}},
                {"Id": "/hostedzone/Z2", "Name": "open.example.", "Config": {"PrivateZone": False}},
                {"Id": "/hostedzone/Z3", "Name": "internal.corp.", "Config": {"PrivateZone": True}},
            ]
        }

    def get_dnssec(self, Id):
        if Id == "Z1":
            return {"Status": {"ServeSignature": "ON", "StatusMessage": "signed"}}
        return {"Status": {"ServeSignature": "OFF", "StatusMessage": "unsigned"}}

    def list_dnssec_key_signing_keys(self, HostedZoneId):
        if HostedZoneId == "Z1":
            return {"KeySigningKeys": [{"KmsArn": "arn:aws:kms:us-east-1:1:key/ksk"}]}
        return {"KeySigningKeys": []}


class _Ecr:
    def describe_repositories(self):
        return {
            "repositories": [
                {"repositoryName": "pay", "encryptionConfiguration": {"encryptionType": "KMS", "kmsKey": "arn:aws:kms:us-east-1:1:key/r"},
                 "imageScanningConfiguration": {"scanOnPush": True}},
                {"repositoryName": "legacy", "encryptionConfiguration": {"encryptionType": "AES256"},
                 "imageScanningConfiguration": {"scanOnPush": False}},
            ]
        }


class _Efs:
    def describe_file_systems(self):
        return {
            "FileSystems": [
                {"FileSystemId": "fs-1", "Encrypted": True, "KmsKeyId": "arn:aws:kms:us-east-1:1:key/e",
                 "LifeCycleState": "available"},
                {"FileSystemId": "fs-2", "Encrypted": False, "LifeCycleState": "available"},
            ]
        }


class _CloudHsm:
    def describe_clusters(self):
        return {
            "Clusters": [
                {"ClusterId": "c-1", "State": "ACTIVE", "HsmType": "hsm1.medium",
                 "BackupPolicy": "DEFAULT", "Hsms": [{"EniId": "eni-1"}]},
                {"ClusterId": "c-2", "State": "DEGRADED", "HsmType": "hsm1.medium", "Hsms": []},
            ]
        }


def test_aws_route53_dnssec_and_private_zones():
    rows = scan_route53(_Route53())
    by_zone = {row["crypto"]["raw_transformation"]: row for row in rows}
    signed = by_zone["signed.example."]
    assert signed["compliance_issue"] is None
    assert signed["metadata"]["dnssec_signing"] is True
    assert signed["metadata"]["signing_kms_arn"] == "arn:aws:kms:us-east-1:1:key/ksk"
    assert by_zone["open.example."]["compliance_issue"] == "DNSSEC_DISABLED"
    # private zones are exempt from the DNSSEC requirement
    assert by_zone["internal.corp."]["compliance_issue"] is None
    assert by_zone["internal.corp."]["metadata"]["private_zone"] is True


def test_aws_ecr_reports_encryption_and_scan_posture():
    rows = scan_ecr(_Ecr(), region="us-east-1")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["pay"]["metadata"]["customer_managed_key"] is True
    assert by_name["pay"]["compliance_issue"] is None
    assert by_name["legacy"]["compliance_issue"] == "IMAGE_SCAN_DISABLED"
    assert by_name["legacy"]["metadata"]["encryption_type"] == "AES256"


def test_aws_efs_flags_unencrypted_filesystem():
    rows = scan_efs(_Efs(), region="us-east-1")
    by_id = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_id["fs-1"]["compliance_issue"] is None
    assert by_id["fs-1"]["algorithm"] == "AES-256"
    assert by_id["fs-2"]["compliance_issue"] == "NO_ENCRYPTION_AT_REST"


def test_aws_cloudhsm_cluster_availability():
    rows = scan_cloudhsm(_CloudHsm(), region="us-east-1")
    by_id = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_id["c-1"]["compliance_issue"] is None
    assert by_id["c-1"]["metadata"]["hsm_count"] == 1
    assert by_id["c-2"]["compliance_issue"] == "HSM_NOT_ACTIVE"


# ------------------------------------------------------------------ Azure


def test_azure_app_service_tls_and_https():
    sites = [
        SimpleNamespace(name="secure", min_tls_version="1.2", https_only=True),
        {"name": "legacy", "properties": {"minTlsVersion": "1.0", "httpsOnly": True}},
        {"name": "plain", "properties": {"minTlsVersion": "1.2", "httpsOnly": False}},
    ]
    rows = scan_app_service(sites, subscription="sub-1")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["secure"]["compliance_issue"] is None
    assert by_name["legacy"]["compliance_issue"] == "WEAK_TLS_VERSION"
    assert by_name["plain"]["compliance_issue"] == "NO_HTTPS_ONLY"


class _Dns:
    class zones:
        @staticmethod
        def list():
            return [
                {"name": "pay.example", "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/dnszones/pay.example",
                 "properties": {"zoneType": "Public"}},
                {"name": "open.example", "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/dnszones/open.example",
                 "properties": {"zoneType": "Public"}},
            ]

    class dnssec_configs:
        @staticmethod
        def get(rg, zone, default):
            if zone == "pay.example":
                return SimpleNamespace(properties=SimpleNamespace(
                    signing_keys=[{"digestAlgorithmType": "SHA256"}],
                    provisioning_state="Succeeded",
                ))
            return SimpleNamespace(properties=SimpleNamespace(signing_keys=[], provisioning_state="Failed"))


def test_azure_dns_dnssec_signing():
    rows = scan_dns(_Dns(), subscription="sub-1")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["pay.example"]["compliance_issue"] is None
    assert by_name["pay.example"]["metadata"]["dnssec_enabled"] is True
    assert by_name["pay.example"]["metadata"]["signing_key_count"] == 1
    assert by_name["open.example"]["compliance_issue"] == "DNSSEC_DISABLED"


def test_azure_acr_policies():
    regs = [
        {"name": "hardened", "properties": {
            "encryption": {"status": "enabled", "keyVaultProperties": {"keyIdentifier": "kv/1"}},
            "policies": {"quarantinePolicy": {"status": "enabled"}, "trustPolicy": {"status": "enabled"}}}},
        {"name": "loose", "properties": {
            "encryption": {"status": "enabled"},
            "policies": {"quarantinePolicy": {"status": "disabled"}, "trustPolicy": {"status": "disabled"}}}},
    ]
    rows = scan_acr(regs, subscription="sub-1")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["hardened"]["compliance_issue"] is None
    assert by_name["hardened"]["metadata"]["customer_managed_key"] is True
    assert by_name["loose"]["compliance_issue"] == "QUARANTINE_DISABLED"


class _Vpn:
    class virtual_network_gateways:
        @staticmethod
        def list():
            return [SimpleNamespace(
                name="gw",
                id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkGateways/gw",
                gateway_type="Vpn", vpn_type="RouteBased",
            )]

    class virtual_network_gateway_connections:
        @staticmethod
        def list(rg):
            return [
                {"name": "strong", "properties": {"ikeVersion": "IKEv2", "ipsecPolicies": [
                    {"dhGroup": "DHGroup14", "ipsecEncryption": "AES256", "ipsecIntegrity": "SHA256"}]}},
                {"name": "weak", "properties": {"ikeVersion": "IKEv1", "ipsecPolicies": [
                    {"dhGroup": "DHGroup2", "ipsecEncryption": "DES3", "ipsecIntegrity": "MD5"}]}},
            ]


def test_azure_vpn_gateway_flags_weak_ike():
    rows = scan_vpn_gateway(_Vpn(), subscription="sub-1")
    assert len(rows) == 1
    gw = rows[0]
    assert gw["compliance_issue"] == "WEAK_IPSEC_POLICY"
    assert gw["metadata"]["weak_connections"] == ["weak"]


def test_azure_managed_hsm_controls():
    pools = [
        SimpleNamespace(name="sec", enable_purge_protection=True, enable_soft_delete=True,
                        security_domain="initialized"),
        {"name": "risky", "properties": {"enablePurgeProtection": False, "enableSoftDelete": False}},
    ]
    rows = scan_managed_hsm(pools, subscription="sub-1")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["sec"]["compliance_issue"] is None
    issue = by_name["risky"]["compliance_issue"]
    assert "NO_PURGE_PROTECTION" in issue and "NO_SOFT_DELETE" in issue


# ------------------------------------------------------------------ GCP


def test_gcp_cloud_dns_dnssec_state():
    zones = [
        {"name": "signed", "dnsName": "signed.example.", "visibility": "public",
         "dnssecConfig": {"state": "on", "kskAlgorithm": "ecdsap256sha256", "zskAlgorithm": "ecdsap256sha256"}},
        {"name": "open", "dnsName": "open.example.", "visibility": "public",
         "dnssecConfig": {"state": "off"}},
    ]
    rows = scan_cloud_dns(zones, project="p")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["signed"]["compliance_issue"] is None
    assert by_name["signed"]["metadata"]["dnssec_enabled"] is True
    assert by_name["open"]["compliance_issue"] == "DNSSEC_DISABLED"


def test_gcp_cloud_dns_weak_algorithm():
    rows = scan_cloud_dns(
        [{"name": "weak", "visibility": "public",
          "dnssecConfig": {"state": "on", "kskAlgorithm": "rsasha1", "zskAlgorithm": "rsasha1"}}],
        project="p",
    )
    assert rows[0]["compliance_issue"] == "WEAK_DNSSEC_ALGORITHM"


def test_gcp_memorystore_transit_encryption():
    instances = [
        {"name": "projects/p/locations/us-central1/instances/secure",
         "transitEncryptionMode": "SERVER_AUTHENTICATION", "authEnabled": True},
        {"name": "projects/p/locations/us-central1/instances/bare",
         "transitEncryptionMode": "DISABLED", "authEnabled": False},
    ]
    rows = scan_memorystore(instances, project="p")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["secure"]["compliance_issue"] is None
    assert by_name["secure"]["metadata"]["transit_encryption_mode"] == "SERVER_AUTHENTICATION"
    assert by_name["bare"]["compliance_issue"] == "NO_TRANSIT_ENCRYPTION"


def test_gcp_cloud_run_cmek():
    services = [
        {"name": "projects/p/locations/us-central1/services/api",
         "template": {"spec": {"encryptionKey": "projects/p/locations/global/keyRings/r/cryptoKeys/k",
                               "encryptionKeyRevocationAction": "PREVENT_NEW"}}},
        {"name": "projects/p/locations/us-central1/services/web",
         "template": {"spec": {}}},
    ]
    rows = scan_cloud_run(services, project="p")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["api"]["compliance_issue"] is None
    assert by_name["api"]["metadata"]["customer_managed_key"] is True
    assert by_name["api"]["metadata"]["encryption_key_revocation_action"] == "PREVENT NEW"
    assert by_name["web"]["compliance_issue"] == "NO_CMEK"
