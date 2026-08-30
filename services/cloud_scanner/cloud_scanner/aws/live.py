"""Optional live AWS scan. Requires boto3 and credentials; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.aws import scanners


def live_enabled(flag: bool | None = None) -> bool:
    if flag is not None:
        return bool(flag)
    return os.environ.get("CRYPTOSCAN_CLOUD_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def _session():
    import boto3  # type: ignore

    return boto3.Session()


def _max_regions(env_name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(env_name) or default))
    except ValueError:
        return default


def _regions(session, requested: list[str] | None, telemetry=None) -> list[str]:
    """Region list with recorded truncation — dropped regions are never silent."""
    if requested:
        cap = _max_regions("CRYPTOSCAN_CLOUD_MAX_REGIONS_REQUESTED", 16)
        if len(requested) > cap:
            if telemetry:
                telemetry.record_truncation("AWS", "regions", "requested", cap)
            return requested[:cap]
        return requested
    try:
        names = session.get_available_regions("kms") or []
    except Exception:
        names = []
    if not names:
        names = [session.region_name or "us-east-1"]
    cap = _max_regions("CRYPTOSCAN_CLOUD_MAX_REGIONS", 8)
    if len(names) > cap:
        if telemetry:
            telemetry.record_truncation("AWS", "regions", "discovered", cap)
        return names[:cap]
    return names


def scan_aws(
    *,
    regions: list[str] | None = None,
    session=None,
    role_arn: str | None = None,
    telemetry=None,
) -> list[dict[str, Any]]:
    return scan_aws_detailed(regions=regions, session=session, role_arn=role_arn, telemetry=telemetry)["findings"]


def scan_aws_detailed(
    *,
    regions: list[str] | None = None,
    session=None,
    role_arn: str | None = None,
    telemetry=None,
) -> dict[str, Any]:
    """Live AWS scan with telemetry: what ran, what failed, what truncated.

    Provider-level failures (no credentials, no boto3) are recorded and
    reported — never silently turned into an empty success."""
    from cloud_scanner.core.reliability import ScanTelemetry

    tele: ScanTelemetry | None = telemetry
    if tele is None:
        tele = ScanTelemetry()
    tele.providers_attempted.add("AWS")
    try:
        sess = session
        if sess is None and role_arn:
            from cloud_scanner.aws.auth.iam_role_assumer import assume_role

            creds = assume_role(role_arn)
            if creds:
                import boto3  # type: ignore

                sess = boto3.Session(
                    aws_access_key_id=creds.get("AccessKeyId"),
                    aws_secret_access_key=creds.get("SecretAccessKey"),
                    aws_session_token=creds.get("SessionToken"),
                )
        sess = sess or _session()
    except Exception as exc:  # includes missing boto3 / credentials
        tele.record_error("AWS", "session", "global", exc)
        return {"findings": [], "provider": "AWS", "regions": []}

    findings: list[dict[str, Any]] = []
    region_list = _regions(sess, regions, telemetry=tele)
    cloudfront_done = False
    for region in region_list:
        for service, fn in (
            ("kms", scanners.scan_kms),
            ("s3", scanners.scan_s3),
            ("rds", scanners.scan_rds),
            ("elbv2", scanners.scan_elb),
            ("acm", scanners.scan_acm),
            ("secretsmanager", scanners.scan_secretsmanager),
            ("lambda", scanners.scan_lambda),
            ("apigateway", scanners.scan_apigateway),
            ("ec2", scanners.scan_ebs),
            ("ssm", scanners.scan_ssm),
            ("dynamodb", scanners.scan_dynamodb),
            ("sqs", scanners.scan_sqs),
            ("sns", scanners.scan_sns),
            ("opensearch", scanners.scan_opensearch),
            ("eks", scanners.scan_eks),
            ("redshift", scanners.scan_redshift),
            ("ecr", scanners.scan_ecr),
            ("efs", scanners.scan_efs),
            ("cloudhsmv2", scanners.scan_cloudhsm),
        ):
            try:
                client = sess.client(service, region_name=region)
                findings.extend(fn(client, region=region, telemetry=tele))
            except Exception as exc:
                tele.record_error("AWS", service, region, exc)
                continue
        if not cloudfront_done:
            cloudfront_done = True
            try:
                findings.extend(
                    scanners.scan_cloudfront(sess.client("cloudfront", region_name="us-east-1"), telemetry=tele)
                )
            except Exception as exc:
                tele.record_error("AWS", "cloudfront", "global", exc)
    # Route 53 + its DNSSEC signing are global (us-east-1 endpoint)
    try:
        findings.extend(scanners.scan_route53(sess.client("route53", region_name="us-east-1"), telemetry=tele))
    except Exception as exc:
        tele.record_error("AWS", "route53", "global", exc)
    return {"findings": findings, "provider": "AWS", "regions": region_list}
