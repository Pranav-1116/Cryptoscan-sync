#!/usr/bin/env python3
"""Capture original explicit native snapshot + pre-approved expected truth.

Runs existing ordinary-user native collectors, NOT a full-worker sandbox. The
Windows branch must run on Windows. No substitute observations or system setup.
"""

import argparse
import hashlib
import platform
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import read_public, read_json, exclusive_public
from inventory.collection import OfflineLinuxCollector, OfflineWindowsCollector
from inventory.host import elevated
from shared_models.collection import TargetSpec
from shared_models.qualification_acceptance import NativePlan, NativeEvidence, evaluate_native
from shared_models.tpm_quote_verification import canonical, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--category", choices=["systemd", "dmi", "tpm", "windows"], required=True)
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--source-lock", type=Path, required=True)
    p.add_argument("--approved-plan-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        target = TargetSpec.model_validate(read_json(args.target))
        plan = NativePlan.model_validate(read_json(args.plan))
        if sha(plan) != args.approved_plan_sha256 or plan.target_sha256 != sha(target):
            raise ValueError("Expected truth must be approved before measurement")
        # Validate plan shape before acquisition, not after executing native reads.
        from shared_models.host_collection import HostFact
        from shared_models.host_runtime import RuntimeFact
        from shared_models.windows_images import WindowsImageFact
        from shared_models.windows_cng import WindowsCngFact, unsupported_expected_value

        fields = (
            set(HostFact.model_fields)
            | set(RuntimeFact.model_fields)
            | set(WindowsImageFact.model_fields)
            | set(WindowsCngFact.model_fields)
        )
        if (
            not target.manifest
            or {e.input_id for e in plan.expected} != {i.input_id for i in target.manifest.inputs}
            or len({e.input_id for e in plan.expected}) != len(plan.expected)
        ):
            raise ValueError("Exact plan scope required")
        if any(
            not f or "kind" not in f or set(f) - fields or any(unsupported_expected_value(k, v) for k, v in f.items())
            for e in plan.expected
            for f in e.facts
        ):
            raise ValueError("Invalid expected truth")
        if elevated():
            raise ValueError("Ordinary native user required")
        expected = "Windows" if args.category == "windows" else "Linux"
        if platform.system() != expected:
            raise ValueError("Required native OS unavailable")
        source_sha = hashlib.sha256(read_public(args.source_lock, 65536)).hexdigest()
        collector = OfflineWindowsCollector() if args.category == "windows" else OfflineLinuxCollector()
        snapshot = collector.collect(target)
        evidence = NativeEvidence(
            category=args.category,
            source_lock_sha256=source_sha,
            native_system=platform.system(),
            target=target,
            plan=plan,
            snapshot=snapshot,
        )
        report = evaluate_native(evidence)
        data = canonical(evidence)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("Native artifact exceeds verification bound")
        exclusive_public(args.output, data)
        print(canonical(report).decode())
        return 0 if report["verdict"] == "PASS_SCOPED_NATIVE_EVIDENCE" else 2
    except Exception:
        print(
            "NATIVE_QUALIFICATION_REFUSED: invalid/unavailable platform, scope, truth or output; no substitutions",
            file=sys.stderr,
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
