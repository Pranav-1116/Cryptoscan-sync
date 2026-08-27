from types import SimpleNamespace

from cloud_scanner.gcp.scanners import (
    scan_cloud_kms,
    scan_cloud_sql,
    scan_gcs,
    scan_gke,
    scan_load_balancer,
    scan_pubsub,
    scan_secret_manager,
)
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


# -------------------------------------------------------------------------- #
# new scanners: secretmanager / pubsub / gke
# -------------------------------------------------------------------------- #


class _Secrets:
    def list_secrets(self, request):
        return [
            SimpleNamespace(
                name="projects/p/secrets/cm-secret",
                replication=SimpleNamespace(
                    customer_managed_encryption=SimpleNamespace(kms_key_name="projects/p/locations/global/cryptoKeys/k")
                ),
            ),
            SimpleNamespace(name="projects/p/secrets/plain", replication=SimpleNamespace()),
        ]


class _PubSub:
    def list_topics(self, request):
        return [
            SimpleNamespace(name="projects/p/topics/orders", kms_key_name="projects/p/locations/global/cryptoKeys/k"),
            SimpleNamespace(name="projects/p/topics/bare", kms_key_name=None),
        ]


class _Gke:
    def projects(self):
        return self

    def locations(self):
        return self

    def clusters(self):
        return self

    def list(self, parent):
        class _Req:
            def execute(self_inner):
                return {
                    "clusters": [
                        {"name": "bank", "encryptionConfig": {"keyName": "projects/p/locations/global/cryptoKeys/k"}},
                        {"name": "open", "encryptionConfig": None},
                    ]
                }

        return _Req()


def test_scan_secret_manager_reports_cmek():
    rows = scan_secret_manager(_Secrets(), project="p")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["cm-secret"]["metadata"]["customer_managed_key"] is True
    assert by_name["plain"]["metadata"]["customer_managed_key"] is False


def test_scan_pubsub_flags_unencrypted_topic():
    rows = scan_pubsub(_PubSub(), project="p")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["orders"]["compliance_issue"] is None
    assert by_name["bare"]["compliance_issue"] == "NO_ENCRYPTION_AT_REST"


def test_scan_gke_reports_secrets_encryption():
    rows = scan_gke(_Gke(), project="p")
    by_name = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_name["bank"]["compliance_issue"] is None
    assert by_name["open"]["compliance_issue"] == "NO_ENV_ENCRYPTION"


def test_gcp_caps_record_truncation_instead_of_silent_drop():
    from cloud_scanner.core.reliability import ScanTelemetry

    buckets = [SimpleNamespace(name=f"b{i:03d}", default_kms_key_name=None) for i in range(25)]

    class _ManyBuckets:
        def list_buckets(self):
            return buckets

    telemetry = ScanTelemetry(max_resources=12)
    rows = scan_gcs(_ManyBuckets(), project="p", telemetry=telemetry)
    assert len(rows) == 12
    assert telemetry.truncations == [{"provider": "GCP", "service": "storage", "region": "p", "cap": "12"}]
