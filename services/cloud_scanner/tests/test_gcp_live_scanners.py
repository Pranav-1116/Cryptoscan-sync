from types import SimpleNamespace

from cloud_scanner.gcp.scanners import scan_cloud_kms, scan_cloud_sql, scan_gcs, scan_load_balancer
from cloud_scanner.gcp.scanners import map_gcp_kms_algorithm


class _Kms:
    def list_crypto_keys(self, request):
        template = SimpleNamespace(
            algorithm=SimpleNamespace(name="RSA_SIGN_PSS_2048_SHA256"),
            protection_level=SimpleNamespace(name="HSM"),
        )
        return [
            SimpleNamespace(
                name="projects/p/locations/global/keyRings/r/cryptoKeys/k",
                version_template=template,
                purpose=SimpleNamespace(name="ASYMMETRIC_SIGN"),
                rotation_period=SimpleNamespace(seconds=7776000),
            )
        ]


class _Storage:
    def list_buckets(self):
        return [SimpleNamespace(name="logs", default_kms_key_name=None)]


def test_gcp_kms_maps_rsa():
    assert map_gcp_kms_algorithm("RSA_SIGN_PSS_2048_SHA256") == ("RSA", 2048)
    findings = scan_cloud_kms(_Kms(), project="p")
    assert findings[0]["algorithm"] == "RSA"
    assert findings[0]["key_size"] == 2048
    assert findings[0]["metadata"]["protection_level"] == "HSM"


def test_gcp_gcs_and_sql_and_ssl():
    buckets = scan_gcs(_Storage(), project="p")
    assert buckets[0]["source"]["type"] == "GCP_STORAGE_BUCKET"
    sql = scan_cloud_sql(
        [{"name": "pay", "settings": {"diskEncryptionConfiguration": None}}],
        project="p",
    )
    assert sql[0]["algorithm"] == "AES-256"
    ssl = scan_load_balancer([{"name": "legacy", "minTlsVersion": "TLS_1_0"}], project="p")
    assert ssl[0]["compliance_issue"] == "WEAK_TLS_VERSION"
