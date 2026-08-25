from cloud_scanner.core.scanner import CloudScanner
from cloud_scanner.iac.terraform import parse_terraform


def test_terraform_flags_unencrypted_s3_and_rds(tmp_path):
    path = tmp_path / "main.tf"
    path.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
resource "aws_db_instance" "main" {
  storage_encrypted = false
}
resource "aws_kms_key" "data" {
  customer_master_key_spec = "RSA_2048"
  enable_key_rotation      = false
}
resource "aws_lb_listener" "front" {
  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"
}
resource "google_kms_crypto_key" "k" {
  name = "k"
}
"""
    )
    findings = parse_terraform(path)
    issues = {row["compliance_issue"] for row in findings if row.get("compliance_issue")}
    assert "NO_ENCRYPTION" in issues
    assert "NO_ENCRYPTION_AT_REST" in issues
    assert "WEAK_TLS_VERSION" in issues
    kms = next(row for row in findings if row["source"]["type"] == "AWS_KMS_KEY")
    assert kms["algorithm"] == "RSA"
    assert kms["key_size"] == 2048
    assert any(row["metadata"]["cloud_provider"] == "GCP" for row in findings)


def test_cloud_scanner_walks_tree(tmp_path):
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "bucket.tf").write_text('resource "aws_s3_bucket" "x" { bucket = "x" }\n')
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "secret.yaml").write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: tls\ntype: kubernetes.io/tls\ndata: {}\n"
    )
    result = CloudScanner(live=False).scan_filesystem(tmp_path)
    assert result["resources"] >= 2
    assert result["issues"] >= 1
    types = {row["source"]["type"] for row in result["findings"]}
    assert "AWS_S3_BUCKET" in types
    assert "K8S_TLS_SECRET" in types
