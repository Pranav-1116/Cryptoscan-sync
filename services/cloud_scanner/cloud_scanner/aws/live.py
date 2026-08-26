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


def _regions(session, requested: list[str] | None) -> list[str]:
    if requested:
        return requested[:16]
    try:
        names = session.get_available_regions("kms") or []
    except Exception:
        names = []
    if not names:
        names = [session.region_name or "us-east-1"]
    return names[:8]


def scan_aws(*, regions: list[str] | None = None, session=None, role_arn: str | None = None) -> list[dict[str, Any]]:
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
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    region_list = _regions(sess, regions)
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
        ):
            try:
                client = sess.client(service, region_name=region)
                findings.extend(fn(client, region=region))
            except Exception:
                continue
        if not cloudfront_done:
            try:
                findings.extend(scanners.scan_cloudfront(sess.client("cloudfront", region_name="us-east-1")))
                cloudfront_done = True
            except Exception:
                cloudfront_done = True
    return findings
