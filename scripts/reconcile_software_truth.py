#!/usr/bin/env python3
"""Compare retained package evidence to an agreed register; never rescan/claim full host coverage."""

import argparse
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import read_json, exclusive_public
from shared_models.host_collection import HostSnapshot, digest
from shared_models.software_truth import SoftwareTruthPlan, reconcile_software
from shared_models.tpm_quote_verification import canonical


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--approved-plan-sha256", required=True)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        plan = SoftwareTruthPlan.model_validate(read_json(a.plan, limit=1048576))
        if digest(plan) != a.approved_plan_sha256:
            raise ValueError("Reviewed plan changed")
        snapshot = HostSnapshot.model_validate(read_json(a.snapshot, limit=1500000))
        report = reconcile_software(plan, snapshot)
        exclusive_public(a.output, canonical(report))
        return 0 if report["agreed_package_record_coverage_verified"] else 2
    except Exception:
        print("SOFTWARE_TRUTH_REFUSED: scope, plan, snapshot or output; no collection performed", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
