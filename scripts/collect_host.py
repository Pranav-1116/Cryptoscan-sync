#!/usr/bin/env python3
"""Run with the repository's installed inventory/shared-models dependencies.

No upload. Never overwrite an output. Exit 2 means receipts contain gaps, not
an insecure host. The local manifest is an operator assertion; intake separately
checks a durable API approval and preserves IMPORTED, not attested OBSERVED.
"""

import argparse
import json
import os
import sys

from _bootstrap import bootstrap

bootstrap()

from inventory.host import collect
from shared_models.host_collection import HostManifest
from shared_models.qualified_export import bounded_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--manifest")
    source.add_argument(
        "--target-spec", help="Approved target payload; Linux by default, Windows requires candidate opt-in"
    )
    parser.add_argument(
        "--windows-candidate",
        action="store_true",
        help="Explicitly opt into unqualified native Windows offline candidate; no production job admission",
    )
    parser.add_argument(
        "--isolated", action="store_true", help="Fail-closed Linux Landlock/seccomp file stage; requires --target-spec"
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        with open(args.manifest or args.target_spec, "rb") as src:
            raw = src.read(131073)
        value = bounded_json(raw, max_bytes=131072)
        if args.target_spec:
            from shared_models.collection import TargetSpec
            from inventory.collection import OfflineLinuxCollector, OfflineWindowsCollector

            adapter = OfflineWindowsCollector() if args.windows_candidate else OfflineLinuxCollector()
            if args.isolated:
                if args.windows_candidate:
                    raise ValueError("No Windows isolation fallback")
                from inventory.isolation import collect_isolated

                snapshot, _ = collect_isolated(TargetSpec.model_validate(value))
            else:
                snapshot = adapter.collect(TargetSpec.model_validate(value))
        else:
            if args.windows_candidate or args.isolated:
                raise ValueError("Windows candidate opt-in requires target-spec")
            snapshot = collect(HostManifest.model_validate(value))
        raw = json.dumps(snapshot.model_dump(mode="json"), sort_keys=True, indent=2).encode()
        if len(raw) > 1500000:
            raise ValueError("receipt size limit")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(args.output, flags, 0o600), "wb") as out:
            out.write(raw)
        return 0 if all(r.status == "PARSED" for r in snapshot.receipts) else 2
    except (ValueError, OSError):
        print(
            "Host collection refused: invalid manifest, unreadable input or unavailable output. No upload performed.",
            file=sys.stderr,
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
