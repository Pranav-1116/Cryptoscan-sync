#!/usr/bin/env python3
"""Prepare canonical public assessment bytes for an EXTERNAL Ed25519 signer.

Never reads, generates or stores private keys. Does not manufacture test results.
The server verifies signatures and approved exact-estate scope at intake.
"""

import argparse
import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/shared_models"))
from shared_models.launch_assurance import AssessmentReport, SignedReport  # noqa: E402


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical(path):
    with Path(path).open("rb") as source:
        raw = source.read(1500001)
    if len(raw) > 1500000:
        raise ValueError("Report exceeds 1.5 MB limit")
    value = json.loads(raw, object_pairs_hook=unique)
    return AssessmentReport.model_validate(value).model_dump(mode="json")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report", type=Path, help="Assessor-authored AssessmentReport JSON, not a SignedReport envelope"
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="New output file (will not overwrite input or other files)"
    )
    parser.add_argument(
        "--signature-file", type=Path, help="External detached raw 64-byte Ed25519 signature; emit API envelope"
    )
    parser.add_argument(
        "--expected-revision", type=int, help="Current retained report revision; mandatory for envelope"
    )
    args = parser.parse_args()
    try:
        value = canonical(args.report)
        if args.signature_file:
            with args.signature_file.open("rb") as source:
                signature = source.read(65)
            if len(signature) != 64 or args.expected_revision is None:
                raise ValueError("Envelope needs a raw 64-byte signature and --expected-revision")
            value = SignedReport.model_validate(
                {
                    "payload": value,
                    "signature_base64": base64.b64encode(signature).decode(),
                    "expected_revision": args.expected_revision,
                }
            ).model_dump(mode="json")
        elif args.expected_revision is not None:
            raise ValueError("--expected-revision is only for signed envelope assembly")
        with args.output.open("xb") as target:
            target.write(encoded(value))
    except (OSError, ValueError, RecursionError) as exc:
        parser.exit(2, f"Refused: {exc}\n")
    print(f"Wrote {args.output}. External execution, signature and approved server scope are still required.")


if __name__ == "__main__":
    main()
