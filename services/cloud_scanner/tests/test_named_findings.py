from datetime import datetime, timedelta, timezone

from cloud_scanner.common.certificate_finding import CertificateFinding
from cloud_scanner.common.cloud_finding import CloudFinding
from cloud_scanner.common.kms_key_finding import KMSKeyFinding
from cloud_scanner.common.resource_tagger import ResourceTagger
from cloud_scanner.config.settings import load_settings
from cloud_scanner.core.result_submitter import ResultSubmitter
from cloud_scanner.core.scheduler import due_accounts
from cloud_scanner.main import main
from cloud_scanner.models.enums import CloudProvider


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
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    due = due_accounts(
        [{"id": "acct", "last_scan_time": (now - timedelta(days=2)).isoformat(), "scan_frequency": "daily"}],
        now=now,
    )
    assert due and due[0]["due"] is True
    submitted = ResultSubmitter(transport=lambda url, body: {"accepted": True}).submit({"findings": []})
    assert submitted["ok"] is True
    assert CloudProvider.AWS.value == "AWS"
    assert load_settings().live is False


def test_cloud_main_scans_tree(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_kms_key" "k" { customer_master_key_spec = "RSA_2048" }\n')
    out = tmp_path / "out.json"
    assert main([str(tmp_path), "-o", str(out)]) == 0
    assert "findings" in out.read_text(encoding="utf-8")


def test_cloud_findings_carry_key_sizes():
    from cloud_scanner.common.finding import cloud_finding

    des = cloud_finding(
        source_type="AWS_KMS_KEY",
        resource="legacy-key",
        algorithm="DES",
        purpose="KEY_MANAGEMENT",
        file_path="aws://us-east-1/kms/legacy",
    )
    assert des["key_size"] == 56
    aes = cloud_finding(
        source_type="AWS_KMS_KEY",
        resource="data-key",
        algorithm="AES-256",
        purpose="KEY_MANAGEMENT",
        file_path="aws://us-east-1/kms/data",
    )
    assert aes["key_size"] == 256
    triple = cloud_finding(
        source_type="AWS_KMS_KEY",
        resource="old-key",
        algorithm="3DES",
        purpose="KEY_MANAGEMENT",
        file_path="aws://us-east-1/kms/old",
    )
    assert triple["key_size"] == 168
