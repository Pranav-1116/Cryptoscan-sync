from cloud_scanner.aws.mappers import map_acm_key, map_kms_key_spec, map_s3_sse, weak_tls_protocols
from cloud_scanner.aws.scanners import (
    scan_acm,
    scan_cloudfront,
    scan_elb,
    scan_kms,
    scan_lambda,
    scan_rds,
    scan_s3,
)
from cloud_scanner.iac.terraform import parse_terraform


class _Kms:
    def list_keys(self):
        return {"Keys": [{"KeyId": "k1"}]}

    def describe_key(self, KeyId):
        return {
            "KeyMetadata": {
                "KeyId": KeyId,
                "Arn": "arn:aws:kms:us-east-1:1:key/k1",
                "KeySpec": "RSA_2048",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "Origin": "AWS_KMS",
                "KeyManager": "CUSTOMER",
            }
        }

    def get_key_rotation_status(self, KeyId):
        return {"KeyRotationEnabled": False}


class _S3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "open-bucket"}, {"Name": "sealed"}]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": "us-east-1"}

    def get_bucket_encryption(self, Bucket):
        if Bucket == "open-bucket":
            class _Err(Exception):
                response = {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}

            raise _Err()
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }


class _Rds:
    def describe_db_instances(self):
        return {
            "DBInstances": [
                {"DBInstanceIdentifier": "pay", "StorageEncrypted": False, "Engine": "postgres"},
                {"DBInstanceIdentifier": "ok", "StorageEncrypted": True, "Engine": "mysql", "CACertificateIdentifier": "rds-ca"},
            ]
        }


class _Elb:
    def describe_load_balancers(self):
        return {"LoadBalancers": [{"LoadBalancerArn": "arn:lb", "LoadBalancerName": "web"}]}

    def describe_listeners(self, LoadBalancerArn):
        return {
            "Listeners": [
                {
                    "ListenerArn": "arn:lis",
                    "Protocol": "HTTPS",
                    "SslPolicy": "ELBSecurityPolicy-TLS-1-0-2015-04",
                    "Certificates": [{"CertificateArn": "arn:cert"}],
                }
            ]
        }

    def describe_ssl_policies(self, Names):
        return {"SslPolicies": [{"SslProtocols": ["TLSv1", "TLSv1.1"]}]}


class _Acm:
    def list_certificates(self):
        return {"CertificateSummaryList": [{"CertificateArn": "arn:acm"}]}

    def describe_certificate(self, CertificateArn):
        return {
            "Certificate": {
                "CertificateArn": CertificateArn,
                "DomainName": "api.example.com",
                "KeyAlgorithm": "RSA-2048",
                "Status": "ISSUED",
                "SignatureAlgorithm": "SHA256WITHRSA",
            }
        }


class _Cf:
    def list_distributions(self):
        return {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "E1",
                        "ARN": "arn:cf",
                        "DomainName": "d.cloudfront.net",
                        "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1"},
                    }
                ]
            }
        }


class _Lambda:
    def list_functions(self):
        return {
            "Functions": [
                {"FunctionName": "open", "FunctionArn": "arn:lambda:open", "Runtime": "python3.12"},
                {
                    "FunctionName": "sealed",
                    "FunctionArn": "arn:lambda:sealed",
                    "Runtime": "python3.12",
                    "KMSKeyArn": "arn:kms:key",
                    "TracingConfig": {"Mode": "Active"},
                },
            ]
        }


def test_mappers():
    assert map_kms_key_spec("SYMMETRIC_DEFAULT") == ("AES-256", 256)
    assert map_kms_key_spec("RSA_4096") == ("RSA", 4096)
    assert map_s3_sse("aws:kms")[0] == "AES-256"
    assert map_acm_key("RSA_2048") == ("RSA", 2048)
    assert weak_tls_protocols(["TLSv1.1"])


def test_live_scanners_with_fake_clients():
    kms = scan_kms(_Kms(), region="us-east-1")
    assert kms[0]["algorithm"] == "RSA"
    assert kms[0]["key_size"] == 2048
    s3 = scan_s3(_S3(), region="us-east-1")
    issues = {row.get("compliance_issue") for row in s3}
    assert "NO_ENCRYPTION" in issues
    rds = scan_rds(_Rds(), region="us-east-1")
    assert any(row.get("compliance_issue") == "NO_ENCRYPTION_AT_REST" for row in rds)
    elb = scan_elb(_Elb(), region="us-east-1")
    assert elb[0]["compliance_issue"] == "WEAK_TLS_VERSION"
    acm = scan_acm(_Acm(), region="us-east-1")
    assert acm[0]["source"]["type"] == "AWS_ACM_CERTIFICATE"
    cf = scan_cloudfront(_Cf())
    assert cf[0]["compliance_issue"] == "WEAK_TLS_VERSION"
    lambdas = scan_lambda(_Lambda(), region="us-east-1")
    issues = {row.get("compliance_issue") for row in lambdas}
    assert "NO_ENV_ENCRYPTION" in issues
    assert any(row["source"]["type"] == "AWS_LAMBDA_FUNCTION" for row in lambdas)


def test_terraform_covers_acm_cloudfront_and_sql(tmp_path):
    path = tmp_path / "more.tf"
    path.write_text(
        """
resource "aws_acm_certificate" "api" { key_algorithm = "RSA_2048" }
resource "aws_cloudfront_distribution" "cdn" { viewer_certificate { minimum_protocol_version = "TLSv1" } }
resource "aws_api_gateway_domain_name" "d" { security_policy = "TLS_1_0" }
resource "azurerm_mssql_database" "db" { transparent_data_encryption_enabled = false }
resource "azurerm_application_gateway" "gw" { ssl_policy { min_protocol_version = "TLSv1_0" } }
resource "google_sql_database_instance" "db" { name = "db" }
"""
    )
    findings = parse_terraform(path)
    types = {row["source"]["type"] for row in findings}
    assert "AWS_ACM_CERTIFICATE" in types
    assert "AWS_CLOUDFRONT_DISTRIBUTION" in types
    assert "AWS_API_GATEWAY" in types
    assert "AZURE_SQL_DATABASE" in types
    assert "AZURE_APP_GATEWAY" in types
    assert "GCP_CLOUD_SQL" in types
    assert any(row.get("compliance_issue") == "WEAK_TLS_VERSION" for row in findings)
    assert any(row.get("compliance_issue") == "NO_ENCRYPTION_AT_REST" for row in findings)
