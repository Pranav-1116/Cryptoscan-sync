from cloud_scanner.common.certificate_finding import CertificateFinding
from cloud_scanner.common.cloud_finding import CloudFinding
from cloud_scanner.common.kms_key_finding import KMSKeyFinding
from cloud_scanner.common.resource_tagger import ResourceTagger


def test_named_cloud_findings_round_trip():
    finding = CloudFinding(
        source_type="CLOUD",
        resource="alias/pay",
        purpose="ENCRYPTION",
        file_path="aws:kms:alias/pay",
        algorithm="AES",
        key_size=256,
        provider="AWS",
        issue="no rotation",
    ).to_dict()
    assert finding["algorithm"] == "AES"
    assert finding["metadata"]["resource"] == "alias/pay"
    restored = CloudFinding.from_dict(finding)
    assert restored.resource == "alias/pay"
    kms = KMSKeyFinding(
        source_type="CLOUD",
        resource="key-1",
        purpose="ENCRYPTION",
        file_path="aws:kms:key-1",
        algorithm="SYMMETRIC_DEFAULT",
        rotation_enabled=False,
        customer_managed=True,
        key_spec="SYMMETRIC_DEFAULT",
    ).to_dict()
    assert kms["finding_kind"] == "kms_key"
    assert kms["metadata"]["rotation_enabled"] is False
    cert = CertificateFinding(
        source_type="CLOUD",
        resource="arn:acm:cert",
        purpose="TLS",
        file_path="aws:acm:cert",
        algorithm="RSA",
        key_size=2048,
        not_after="2026-01-01",
        subject="CN=pay.example",
    ).to_dict()
    assert cert["finding_kind"] == "certificate"
    assert cert["metadata"]["subject"] == "CN=pay.example"


def test_resource_tagger_maps_system_from_tags():
    tagged = ResourceTagger([{"id": "sys-1", "name": "payments"}]).apply(
        {
            "file_path": "aws:kms:pay",
            "extra": {"tags": {"cryptoscan:system": "payments"}},
        }
    )
    assert tagged["system_id"] == "sys-1"
    assert tagged["extra"]["system_name"] == "payments"
