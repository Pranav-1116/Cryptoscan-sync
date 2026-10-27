#!/usr/bin/env python3
"""Reconcile every agreed asset x six software surfaces; no scanning or global-completeness claim."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from _bootstrap import bootstrap

bootstrap()
from inventory.qualification_files import read_json, read_public, exclusive_public
from shared_models.software_estate import SoftwareEstatePlan, SoftwareEstatePacket, reconcile_estate
from shared_models.tpm_quote_verification import canonical, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--approved-plan-sha256", required=True)
    p.add_argument("--packet", type=Path, required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        plan = SoftwareEstatePlan.model_validate(read_json(a.plan, limit=4 * 1024 * 1024))
        if sha(plan) != a.approved_plan_sha256:
            raise ValueError("Reviewed estate scope changed")
        packet = SoftwareEstatePacket.model_validate(read_json(a.packet, limit=4 * 1024 * 1024))
        artifacts = {}
        used = 0
        for digest in sorted({r.statement.source_sha256 for r in packet.returns}):
            data = read_public(a.artifacts / digest, min(2 * 1024 * 1024, 16 * 1024 * 1024 - used))
            used += len(data)
            artifacts[digest] = data
        report = reconcile_estate(plan, packet, artifacts, datetime.now(timezone.utc))
        exclusive_public(a.output, canonical(report))
        return 0 if report["agreed_register_record_sets_matched"] else 2
    except Exception:
        print("SOFTWARE_ESTATE_REFUSED: plan, source, producer, time or output; no scanning performed", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
