from cloud_scanner.aws.mappers import map_acm_key, map_kms_key_spec, map_s3_sse, weak_tls_protocols
from cloud_scanner.aws.scanners import (
    scan_acm,
    scan_cloudfront,
    scan_dynamodb,
    scan_ebs,
    scan_eks,
    scan_elb,
    scan_kms,
    scan_lambda,
    scan_opensearch,
    scan_redshift,
    scan_rds,
    scan_s3,
    scan_sns,
    scan_sqs,
    scan_ssm,
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
    ebs = scan_ebs(
        type("Ebs", (), {"describe_volumes": lambda self: {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False}]}})(),
        region="us-east-1",
    )
    assert ebs[0]["compliance_issue"] == "NO_ENCRYPTION_AT_REST"
    ssm = scan_ssm(
        type("Ssm", (), {"describe_parameters": lambda self: {"Parameters": [{"Name": "/app/secret", "Type": "String"}]}})(),
        region="us-east-1",
    )
    assert ssm[0]["compliance_issue"] == "UNENCRYPTED_PARAMETER"


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


# -------------------------------------------------------------------------- #
# new service scanners: dynamodb / sqs / sns / opensearch / eks / redshift
# -------------------------------------------------------------------------- #


class _DynamoDB:
    def list_tables(self, **kwargs):
        return {"TableNames": ["orders"], **kwargs}

    def describe_table(self, TableName):
        if TableName == "orders":
            return {"Table": {"SSEDescription": {"Status": "ENABLED", "KMSMasterKeyArn": "arn:aws:kms:...:key/cm"}}}
        return {"Table": {}}


class _Sqs:
    def list_queues(self, **kwargs):
        return {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/1/payments", "https://sqs.us-east-1.amazonaws.com/1/plain"]}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        if "plain" in QueueUrl:
            return {"Attributes": {}}
        return {"Attributes": {"KmsMasterKeyId": "alias/aws/sqs"}}


class _Sns:
    def list_topics(self, **kwargs):
        return {"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:1:alerts"}]}

    def get_topic_attributes(self, TopicArn):
        return {"Attributes": {"KmsMasterKeyId": "alias/aws/sns"}}


class _OpenSearch:
    def list_domain_names(self, **kwargs):
        return {"DomainNames": [{"DomainName": "audit"}, {"DomainName": "legacy"}]}

    def describe_domain(self, DomainName):
        if DomainName == "audit":
            return {
                "DomainStatus": {
                    "EncryptionAtRestOptions": {"Enabled": True, "KmsKeyId": "arn:aws:kms:...:key/k"},
                    "DomainEndpointOptions": {"TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
                }
            }
        return {
            "DomainStatus": {
                "EncryptionAtRestOptions": {"Enabled": False},
                "DomainEndpointOptions": {"TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"},
            }
        }


class _Eks:
    def list_clusters(self, **kwargs):
        return {"clusters": ["banking"]}

    def describe_cluster(self, name):
        return {"cluster": {"version": "1.30", "encryptionConfig": [{"provider": {"keyArn": "arn:aws:kms:...:key/eks"}}]}}


class _Redshift:
    def describe_clusters(self, **kwargs):
        return {
            "Clusters": [
                {"ClusterIdentifier": "warehouse", "Encrypted": True, "KmsKeyId": "arn:aws:kms:...:key/rs"},
                {"ClusterIdentifier": "legacy", "Encrypted": False},
            ]
        }


def test_scan_dynamodb_reports_sse_and_cmk():
    rows = scan_dynamodb(_DynamoDB(), region="us-east-1")
    assert rows[0]["source"]["type"] == "AWS_DYNAMODB_TABLE"
    assert rows[0]["algorithm"] == "AES-256"
    assert rows[0]["compliance_issue"] is None
    assert rows[0]["metadata"]["cmk"] is True


def test_scan_sqs_flags_unencrypted_queue():
    rows = scan_sqs(_Sqs(), region="us-east-1")
    by_resource = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_resource["payments"]["compliance_issue"] is None
    assert by_resource["plain"]["compliance_issue"] == "NO_ENCRYPTION_AT_REST"


def test_scan_sns_reports_kms_topic():
    rows = scan_sns(_Sns(), region="us-east-1")
    assert rows[0]["source"]["type"] == "AWS_SNS_TOPIC"
    assert rows[0]["algorithm"] == "AES-256"


def test_scan_opensearch_flags_unencrypted_and_weak_tls():
    rows = scan_opensearch(_OpenSearch(), region="us-east-1")
    by_resource = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_resource["audit"]["compliance_issue"] is None
    assert by_resource["legacy"]["compliance_issue"] == "NO_ENCRYPTION_AT_REST"


def test_scan_eks_reports_secrets_encryption_kms():
    rows = scan_eks(_Eks(), region="us-east-1")
    assert rows[0]["source"]["type"] == "AWS_EKS_CLUSTER"
    assert rows[0]["metadata"]["secrets_encryption_kms"].endswith("key/eks")


def test_scan_redshift_flags_unencrypted_cluster():
    rows = scan_redshift(_Redshift(), region="us-east-1")
    by_resource = {row["crypto"]["raw_transformation"]: row for row in rows}
    assert by_resource["warehouse"]["compliance_issue"] is None
    assert by_resource["legacy"]["compliance_issue"] == "NO_ENCRYPTION_AT_REST"


def test_scan_ssm_walks_pages():
    class PagedSsm:
        def __init__(self):
            self.calls = 0

        def describe_parameters(self, **kwargs):
            self.calls += 1
            if kwargs.get("NextToken") == "t1":
                return {"Parameters": [{"Name": "/app/p2", "Type": "SecureString"}]}
            return {"Parameters": [{"Name": "/app/p1", "Type": "String"}], "NextToken": "t1"}

    rows = scan_ssm(PagedSsm(), region="us-east-1")
    assert {row["crypto"]["raw_transformation"] for row in rows} == {"/app/p1", "/app/p2"}
    issues = [row for row in rows if row["compliance_issue"]]
    assert issues[0]["compliance_issue"] == "UNENCRYPTED_PARAMETER"
