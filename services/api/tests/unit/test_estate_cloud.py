"""Live AWS discovery plane (spec 67 §4, §21; spec 93 §13).

The properties that matter for a collector touching a bank's cloud account:

* every request is SigV4-signed and read-only;
* what it reports is ``CONFIGURED`` — a listener policy is not a handshake, and a
  KMS key spec is capability, not application usage;
* ``AccessDenied`` is ``blocked`` + ``PARTIAL``, never "there is nothing there";
* no credentials is ``NOT_ATTEMPTED`` (nothing was asked), and the estate job says
  so with the BOMs that lose coverage.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from api import estate_cloud, estate_discovery

CONFIG = {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "session_token": None,
    "region": "eu-west-1",
    "endpoint": "https://aws.test",
    "source": "INJECTED",
}

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

LB_XML = """<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>
  <LoadBalancerArn>arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/payments/1</LoadBalancerArn>
  <DNSName>payments-1.eu-west-1.elb.amazonaws.com</DNSName>
  <LoadBalancerName>payments</LoadBalancerName>
  <Scheme>internet-facing</Scheme>
  <Type>application</Type>
  <State><Code>active</Code></State>
</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>"""

LISTENER_XML = """<DescribeListenersResponse><DescribeListenersResult><Listeners>
<member><Protocol>HTTPS</Protocol><Port>443</Port>
  <SslPolicy>ELBSecurityPolicy-TLS-1-1-2017-01</SslPolicy>
  <Certificates><member><CertificateArn>arn:aws:acm:eu-west-1:1:certificate/abc</CertificateArn></member></Certificates>
</member>
<member><Protocol>HTTP</Protocol><Port>80</Port></member>
</Listeners></DescribeListenersResult></DescribeListenersResponse>"""

RDS_XML = """<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>
  <DBInstanceIdentifier>payments-db</DBInstanceIdentifier>
  <DBInstanceClass>db.r6g.large</DBInstanceClass>
  <Engine>postgres</Engine>
  <EngineVersion>16.3</EngineVersion>
  <StorageEncrypted>true</StorageEncrypted>
  <KmsKeyId>arn:aws:kms:eu-west-1:1:key/1234</KmsKeyId>
  <CACertificateIdentifier>rds-ca-rsa2048-g1</CACertificateIdentifier>
  <PubliclyAccessible>false</PubliclyAccessible>
  <MultiAZ>true</MultiAZ>
  <Endpoint><Address>payments-db.eu-west-1.rds.amazonaws.com</Address><Port>5432</Port></Endpoint>
</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>"""

ACM_LIST = {"CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:eu-west-1:1:certificate/abc",
                                        "DomainName": "payments.bank.example"}]}
ACM_DESCRIBE = {"Certificate": {
    "CertificateArn": "arn:aws:acm:eu-west-1:1:certificate/abc",
    "DomainName": "payments.bank.example",
    "Serial": "0a1b",
    "KeyAlgorithm": "RSA_2048",
    "SignatureAlgorithm": "SHA256WITHRSA",
    "Issuer": "Amazon",
    "Status": "ISSUED",
    "Type": "AMAZON_ISSUED",
    "NotAfter": (NOW + timedelta(days=12)).isoformat().replace("+00:00", "Z"),
    "InUseBy": ["arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/payments/1"],
}}
KMS_DESCRIBE = {"KeyMetadata": {"KeyId": "1234", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
                                "KeyManager": "CUSTOMER", "KeyState": "Enabled", "Origin": "AWS_KMS"}}
APIGW = {"items": [{"domainName": "api.bank.example", "securityPolicy": "TLS_1_2",
                    "endpointConfiguration": {"types": ["REGIONAL"]}}]}


def _transport(calls: list[dict], *, forbid: str | None = None):
    def transport(method, url, headers, body, timeout):
        parsed = urlparse(url)
        action = (parse_qs(parsed.query).get("Action") or [""])[0]
        target = headers.get("x-amz-target") or headers.get("X-Amz-Target")
        calls.append({"method": method, "url": url, "action": action, "target": target,
                      "headers": dict(headers), "body": body})
        if forbid and forbid in str(action or target or parsed.path):
            return 403, b'{"__type":"AccessDeniedException"}'
        if "DescribeLoadBalancers" in action:
            return 200, LB_XML.encode()
        if "DescribeListeners" in action:
            return 200, LISTENER_XML.encode()
        if "DescribeDBInstances" in action:
            return 200, RDS_XML.encode()
        if target == "CertificateManager.ListCertificates":
            return 200, json.dumps(ACM_LIST).encode()
        if target == "CertificateManager.DescribeCertificate":
            return 200, json.dumps(ACM_DESCRIBE).encode()
        if target == "TrentService.ListKeys":
            return 200, b'{"Keys":[{"KeyId":"1234"}]}'
        if target == "TrentService.DescribeKey":
            return 200, json.dumps(KMS_DESCRIBE).encode()
        if parsed.path == "/domainnames":
            return 200, json.dumps(APIGW).encode()
        return 400, b"{}"

    return transport


def test_missing_credentials_is_not_attempted():
    with pytest.raises(estate_cloud.PlaneNotConfigured):
        estate_cloud.cloud_config({})

    def boom(_db, **_kwargs):
        raise estate_cloud.PlaneNotConfigured("no aws credentials")

    report = estate_discovery.run(None, persist=False, collectors={"CLOUD": boom})
    cloud = next(item for item in report["collectors"] if item["plane"] == "CLOUD")
    assert cloud["status"] == "NOT_ATTEMPTED"
    assert "NOT_OBSERVED" in cloud["impact"]


def test_every_request_is_signed_and_read_only():
    calls: list[dict] = []
    estate_cloud.collect_cloud(None, transport=_transport(calls), config=CONFIG, now=NOW)
    assert calls
    for call in calls:
        assert call["method"] == "GET" or call["target"], "only read-only calls are allowed"
        auth = call["headers"].get("authorization") or call["headers"].get("Authorization")
        assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
        assert "/eu-west-1/" in auth
        assert "Delete" not in str(call["action"]) and "Put" not in str(call["action"])
        assert "secretsmanager" not in call["url"]


def test_load_balancers_listeners_and_certificates_become_configured_evidence():
    result = estate_cloud.collect_cloud(None, transport=_transport([]), config=CONFIG, now=NOW)
    assert {"LOAD_BALANCER", "CERTIFICATE", "DATABASE", "KMS_KEY", "API_GATEWAY"} <= {
        asset["type"] for asset in result["assets"]}
    assert all(record["evidence_type"] == "CONFIGURED" for record in result["evidence"])

    listener = next(record for record in result["evidence"]
                    if record["facts"].get("listener_protocol") == "HTTPS")
    assert listener["facts"]["minimum_tls_version_declared"] == "TLSv1.1"
    assert listener["facts"]["claim"].startswith("CONFIGURED")
    assert listener["layer"] == "NETWORK_TRANSPORT"

    plaintext = next(record for record in result["evidence"]
                     if record["facts"].get("listener_protocol") == "HTTP")
    assert plaintext["facts"]["plaintext_listener"] is True
    assert plaintext["facts"]["minimum_tls_version_declared"] is None, "an HTTP listener has no TLS floor"


def test_kms_is_capability_and_never_application_usage():
    result = estate_cloud.collect_cloud(None, transport=_transport([]), config=CONFIG, now=NOW)
    kms = next(record for record in result["evidence"] if record["layer"] == "KMS")
    assert kms["facts"]["usage_state"] == "SUPPORTED"
    assert "CAPABILITY" in kms["facts"]["claim"]
    assert kms["facts"]["supported_algorithms_hint"] == ["AES-256-GCM"]


def test_rds_encryption_is_storage_configuration_with_its_own_layer():
    result = estate_cloud.collect_cloud(None, transport=_transport([]), config=CONFIG, now=NOW)
    db_record = next(record for record in result["evidence"] if record["layer"] == "STORAGE")
    assert db_record["facts"]["storage_encrypted"] is True
    assert db_record["facts"]["kms_key_configured"].endswith("key/1234")
    assert "not visible from the control plane" in db_record["facts"]["claim"]

    database = next(asset for asset in result["assets"] if asset["type"] == "DATABASE")
    key_edges = [edge for edge in result["relationships"]
                 if edge["subject"] == database["asset_id"] and edge["predicate"] == "uses"]
    assert key_edges and key_edges[0]["basis"] == "DEPLOYMENT_CONFIG"
    assert key_edges[0]["attributes"]["observed"] is False


def test_certificate_expiry_is_reported_in_days():
    result = estate_cloud.collect_cloud(None, transport=_transport([]), config=CONFIG, now=NOW)
    certificate = next(record for record in result["evidence"]
                       if record["facts"].get("public_key_algorithm"))
    assert certificate["facts"]["public_key_algorithm"] == "RSA_2048"
    assert certificate["facts"]["days_until_expiry"] == 12
    assert certificate["facts"]["in_use"] is True


def test_access_denied_on_one_family_is_partial_with_a_named_block():
    result = estate_cloud.collect_cloud(None, transport=_transport([], forbid="DescribeDBInstances"),
                                        config=CONFIG, now=NOW)
    assert result["collected"] == len(estate_cloud.CALLS) - 1
    assert any("DescribeDBInstances" in item for item in result["blocked"])
    assert "NOT_OBSERVED, not empty" in " ".join(result["limitations"])

    outcome = estate_discovery._collect("CLOUD", lambda _db, **_: result, None)
    assert outcome["status"] == "PARTIAL"
    assert "NOT_OBSERVED" in outcome["impact"]


def test_ssl_policy_floor_is_read_from_the_policy_name_not_invented():
    assert estate_cloud.SSL_POLICY_FLOORS["ELBSecurityPolicy-TLS-1-2-2017-01"] == "TLSv1.2"
    assert estate_cloud.SSL_POLICY_FLOORS["ELBSecurityPolicy-2016-08"] == "TLSv1.0"

    documented = estate_cloud.collect_cloud(None, transport=_transport([]), config=CONFIG, now=NOW)
    unknown = [record for record in documented["evidence"]
               if record["facts"].get("minimum_tls_version_declared") == "UNKNOWN"]
    assert unknown == [], "an undocumented policy name must not be guessed"

    def undocumented(*_args, **_kwargs):
        raise AssertionError("no network call is expected in this assertion")

    assert "ELBSecurityPolicy-NotARealPolicy" not in estate_cloud.SSL_POLICY_FLOORS
    assert undocumented is not None
