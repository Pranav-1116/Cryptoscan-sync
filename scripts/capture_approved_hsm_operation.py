#!/usr/bin/env python3
"""One operator-authorized AWS KMS signature. Credentials stay in approved SDK environment."""

import argparse
import os
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import read_json, ChallengeStore
from shared_models.hsm_operation_request import HsmOperationRequest
from shared_models.tpm_quote_verification import canonical, sha
from keyassure.operation_capture import capture


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", type=Path, required=True)
    p.add_argument("--approved-request-sha256", required=True)
    p.add_argument("--state-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--acknowledge-provider-sign", action="store_true", required=True)
    a = p.parse_args()
    try:
        request = HsmOperationRequest.model_validate(read_json(a.request))
        if sha(request) != a.approved_request_sha256:
            raise ValueError("Reviewed request changed")
        from datetime import datetime, timezone

        if not request.approval.not_before <= datetime.now(timezone.utc) < request.approval.expires_at:
            raise ValueError("Approval not current")
        with ChallengeStore(a.state_dir) as ledger:
            with os.fdopen(os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as out:
                # Fail closed on crash: authorization is attempted once, even on provider failure.
                ledger.write(
                    sha(request)[:32],
                    ".hsm-attempt.json",
                    canonical({"request_sha256": sha(request), "state": "ATTEMPT_RESERVED"}),
                )
                import boto3
                from botocore.config import Config
                from keyassure.hsm_backends import AwsKmsBackend

                # Explicit endpoint avoids environment URL redirects; ordinary SDK credentials are never read/printed here.
                import re

                partition = "amazonaws.com.cn" if request.region.startswith("cn-") else "amazonaws.com"
                if not re.fullmatch(r"[a-z0-9-]+", request.region):
                    raise ValueError("Invalid region")
                client = boto3.client(
                    "kms",
                    region_name=request.region,
                    endpoint_url=f"https://kms.{request.region}.{partition}",
                    config=Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 0}),
                )
                report = capture(request, AwsKmsBackend(client=client))
                ledger.write(sha(request)[:32], ".hsm-result.json", canonical(report))
                out.write(canonical(report))
                out.flush()
                os.fsync(out.fileno())
        return 0
    except Exception:
        print(
            "HSM_OPERATION_REFUSED: approval, state, SDK or signature; provider details withheld; do not retry consumed approval",
            file=sys.stderr,
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
