#!/usr/bin/env python3
"""Actual native fixture runner. A missing interface fails; never skip-to-PASS.

Targets/expectations are independent operator inputs, not customer discovery.
Results qualify only those inputs and assertions, never production or a bank.
"""

import argparse
import json
import os
import platform
from pathlib import Path
from _bootstrap import bootstrap

bootstrap()
from pydantic import Field
from shared_models.host_common import Strict
from shared_models.collection import TargetSpec
from shared_models.host_collection import Token, digest
from shared_models.qualified_export import bounded_json
from inventory.collection import OfflineLinuxCollector, OfflineWindowsCollector
from inventory.host import elevated


class ExpectedInput(Strict):
    input_id: Token
    facts: list[dict] = Field(min_length=1, max_length=1000)


class FixturePlan(Strict):
    schema_version: str = Field(pattern=r"^cryptoscan.native-fixture/v1$")
    target_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected: list[ExpectedInput] = Field(min_length=1, max_length=100)
    reviewer_reference: Token


def validate_plan(target, plan):
    from shared_models.host_collection import HostFact
    from shared_models.host_runtime import RuntimeFact
    from shared_models.windows_images import WindowsImageFact

    if (
        not target.manifest
        or digest(target) != plan.target_sha256
        or {i.input_id for i in target.manifest.inputs} != {e.input_id for e in plan.expected}
        or len({e.input_id for e in plan.expected}) != len(plan.expected)
    ):
        raise ValueError("Fixture scope mismatch")
    fields = set(HostFact.model_fields) | set(RuntimeFact.model_fields) | set(WindowsImageFact.model_fields)
    for expected in plan.expected:
        for pattern in expected.facts:
            if (
                not pattern
                or "kind" not in pattern
                or set(pattern) - fields
                or any(isinstance(v, (dict, list)) for v in pattern.values())
            ):
                raise ValueError("Invalid fixture assertion")


def evaluate(target, plan, snapshot):
    if (
        digest(target) != plan.target_sha256
        or {i.input_id for i in target.manifest.inputs} != {e.input_id for e in plan.expected}
        or len({e.input_id for e in plan.expected}) != len(plan.expected)
    ):
        raise ValueError("Fixture scope mismatch")
    validate_plan(target, plan)
    expected = {e.input_id: e for e in plan.expected}
    results = []
    for receipt in snapshot.receipts:
        actual = [f.model_dump(mode="json") for f in receipt.facts]
        wanted = expected[receipt.input_id].facts
        # Exact expected fact count; assertions are explicit known scalar fields,
        # not scripts, regexes or arbitrary SQL/path checks.
        matched = receipt.status == "PARSED" and len(actual) == len(wanted)
        used = set()
        for pattern in wanted:
            if (
                not pattern
                or "kind" not in pattern
                or any(not isinstance(k, str) or isinstance(v, (dict, list)) for k, v in pattern.items())
            ):
                raise ValueError("Invalid fixture assertion")
            indices = [
                i
                for i, f in enumerate(actual)
                if i not in used and all(k in f and type(f[k]) is type(v) and f[k] == v for k, v in pattern.items())
            ]
            if not indices:
                matched = False
            else:
                used.add(indices[0])
        results.append(
            {
                "input_id": receipt.input_id,
                "status": receipt.status,
                "reason": receipt.reason,
                "expected_facts": len(wanted),
                "actual_facts": len(actual),
                "matches_expected_truth": matched,
            }
        )
    return {
        "verdict": "PASS_SCOPED_FIXTURE"
        if all(r["matches_expected_truth"] for r in results)
        else "FAIL_GAPS_OR_TRUTH_MISMATCH",
        "target_sha256": digest(target),
        "snapshot_sha256": digest(snapshot),
        "reviewer_reference": plan.reviewer_reference,
        "native_platform": platform.system(),
        "architecture": platform.machine(),
        "results": results,
        "independent_review_verified": False,
        "host_identity_attested": False,
        "production_execution_qualified": False,
    }


def read(path):
    with open(path, "rb") as src:
        return bounded_json(src.read(131073), max_bytes=131072)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--expectations", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--windows-candidate", action="store_true")
    mode.add_argument("--isolated", action="store_true", help="Require actual Linux Landlock/seccomp, never fall back")
    args = p.parse_args()
    try:
        target = TargetSpec.model_validate(read(args.target))
        plan = FixturePlan.model_validate(read(args.expectations))
        validate_plan(target, plan)
        if elevated():
            raise ValueError("Ordinary native user required")
        collector = OfflineWindowsCollector() if args.windows_candidate else OfflineLinuxCollector()
        isolation = None
        if args.isolated:
            from inventory.isolation import collect_isolated

            snapshot, isolation = collect_isolated(target)
        else:
            snapshot = collector.collect(target)
        report = evaluate(target, plan, snapshot)
        if isolation is not None:
            report["isolation"] = isolation
        raw = json.dumps(report, sort_keys=True, indent=2).encode()
        with os.fdopen(
            os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb"
        ) as out:
            out.write(raw)
        return 0 if report["verdict"] == "PASS_SCOPED_FIXTURE" else 2
    except (ValueError, OSError, KeyError, TypeError):
        print("Native qualification refused: platform/scope/fixture/output invalid; no substituted observations")
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
