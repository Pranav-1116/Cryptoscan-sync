#!/usr/bin/env python3
"""Issue a bounded local challenge or verify externally produced public TPM bytes.

Does not create keys, enroll a device, run TPM commands, or enable production.
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import ChallengeStore, read_public, read_json, exclusive_public
from shared_models.tpm_quote_verification import (
    QuotePolicy,
    QuoteChallenge,
    verify_quote,
    qualifying_data,
    canonical,
    sha,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True, help="Existing verifier-owned mode-0700 directory")
    parser.add_argument("--policy", type=Path, required=True, help="Trusted operator-enrolled public AK/PCR policy")
    sub = parser.add_subparsers(dest="action", required=True)
    issue = sub.add_parser("issue")
    issue.add_argument(
        "--scope", type=Path, required=True, help="Exact campaign/tenant/target/source/snapshot/claim JSON"
    )
    issue.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--challenge-id", required=True)
    verify.add_argument("--attestation", type=Path, required=True, help="Raw TPMS_ATTEST bytes, not a TPM2B wrapper")
    verify.add_argument("--signature", type=Path, required=True, help="TPMT_SIGNATURE bytes")
    verify.add_argument("--pcrs", type=Path, required=True, help="Exact index-to-SHA256 PCR JSON")
    verify.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = QuotePolicy.model_validate(read_json(args.policy, 16384))
        now = datetime.now(timezone.utc)
        with ChallengeStore(args.state) as state:
            if args.action == "issue":
                scope = read_json(args.scope, 8192)
                reserved = {
                    "schema_version",
                    "challenge_id",
                    "nonce",
                    "host_id",
                    "policy_sha256",
                    "issued_at",
                    "expires_at",
                }
                if not isinstance(scope, dict) or set(scope) & reserved:
                    raise ValueError("Caller cannot supply verifier challenge fields")
                challenge = QuoteChallenge(
                    **scope,
                    challenge_id=secrets.token_hex(16),
                    nonce=secrets.token_hex(32),
                    host_id=policy.host_id,
                    policy_sha256=sha(policy),
                    issued_at=now,
                    expires_at=now + timedelta(minutes=5),
                )
                if challenge.tenant_id != policy.tenant_id:
                    raise ValueError("Challenge tenant must match enrollment policy")
                state.issue(challenge)
                output = {
                    "challenge": challenge.model_dump(mode="json"),
                    "qualifying_data_hex": qualifying_data(challenge).hex(),
                }
            else:
                challenge = state.get(args.challenge_id)
                output = verify_quote(
                    policy,
                    challenge,
                    read_public(args.attestation, 4096),
                    read_public(args.signature, 1024),
                    read_json(args.pcrs, 8192),
                    now,
                )
                state.consume(challenge, output)
            exclusive_public(args.output, canonical(output))
        return 0
    except Exception:
        print(
            "TPM_QUOTE_REFUSED: invalid, expired, replayed, unavailable or untrusted evidence; no production enablement",
            file=sys.stderr,
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
