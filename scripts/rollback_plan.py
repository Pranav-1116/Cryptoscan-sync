#!/usr/bin/env python3
"""Create a non-destructive release rollback plan.

The command validates the target release lock and writes an operator plan. It
does not stop services, change traffic, run migrations, restore data, or call a
production control plane. Execution remains an explicitly approved operator
procedure after the release, database and evidence checks are reviewed.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.rollback-plan/1"
SERVICES = ("api", "worker", "neo4j")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _lock(release: Path) -> dict[str, str]:
    path = release / "release-image-lock.json"
    if not path.is_file():
        raise ValueError(f"release lock missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        digests = payload["digests"]
        result = {service: str(digests[service]).lower() for service in SERVICES}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid release lock: {type(exc).__name__}") from exc
    invalid = [service for service, digest in result.items() if not _SHA256.fullmatch(digest)]
    if invalid:
        raise ValueError(f"release lock has invalid digests for: {', '.join(invalid)}")
    return result


def build_plan(target: Path, current: Path | None = None) -> dict[str, Any]:
    target = target.resolve()
    if not target.is_dir():
        raise ValueError(f"target release directory not found: {target}")
    target_digests = _lock(target)
    current_digests = _lock(current.resolve()) if current else None
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_release": str(target),
        "current_release": str(current.resolve()) if current else None,
        "target_image_digests": target_digests,
        "current_image_digests": current_digests,
        "steps": [
            "obtain change-approval and declare the rollback window",
            "verify the target release lock and signed release evidence",
            "confirm a current database backup and compatible migration state",
            "drain traffic using the deployment's readiness mechanism",
            "apply the target release manifests through the approved deployment controller",
            "run authenticated health, readiness, migration and evidence-chain checks",
            "restore traffic only after all checks pass and record the result",
        ],
        "execution": {
            "status": "PLAN_ONLY",
            "commands_executed": False,
            "production_mutation": False,
            "destructive_action": False,
            "operator_must_supply": [
                "approved target release",
                "deployment-controller or Compose context",
                "database compatibility and backup evidence",
                "change and incident record",
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True, help="rendered release directory to roll back to")
    parser.add_argument("--current", type=Path, help="currently deployed rendered release directory")
    parser.add_argument("--out", type=Path, help="write the plan as JSON")
    args = parser.parse_args(argv)
    try:
        plan = build_plan(args.target, args.current)
    except ValueError as exc:
        print(f"Rollback plan: FAIL: {exc}")
        return 1
    payload = json.dumps(plan, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    print(f"Rollback plan: PLAN_ONLY -> {plan['target_release']}")
    print("No deployment, traffic, database, restore, or destructive command was executed.")
    if not args.out:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
