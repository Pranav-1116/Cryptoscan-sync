#!/usr/bin/env python3
"""Run the bundled sample scan so a fresh deploy has inventory to inspect."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("CRYPTOSCAN_ROOT", str(ROOT))
sys.path[:0] = [
    str(ROOT / "shared" / "shared_config"),
    str(ROOT / "shared" / "shared_logging"),
    str(ROOT / "shared" / "shared_models"),
    str(ROOT / "services" / "api"),
    str(ROOT / "services" / "database"),
    str(ROOT / "services" / "scanner"),
    str(ROOT / "services" / "evidence"),
    str(ROOT / "services" / "normalization"),
    str(ROOT / "services" / "policy"),
    str(ROOT / "services" / "drift"),
    str(ROOT / "services" / "worker"),
    str(ROOT / "services" / "deduplication"),
    str(ROOT / "services" / "cbom"),
    str(ROOT / "services" / "container_scanner"),
    str(ROOT / "services" / "network_scanner"),
    str(ROOT / "services" / "cloud_scanner"),
    str(ROOT / "services" / "graph_engine"),
    str(ROOT / "services" / "business_context"),
    str(ROOT / "services" / "quantum"),
    str(ROOT / "services" / "remediation"),
    str(ROOT / "services" / "reporting"),
    str(ROOT / "services" / "ot_scanner"),
    str(ROOT / "services" / "vendor_intel"),
    str(ROOT / "services" / "agility"),
]


def main() -> None:
    from db.connection.session import SessionLocal, init_db
    from db.repositories.job_repository import JobRepository
    from worker.pipeline.pipeline_runner import PipelineRunner

    init_db()
    session = SessionLocal()
    try:
        job = JobRepository(session).create_job(
            job_type="MANUAL",
            target_repo="local://demo/vulnerable-app",
            target_branch="main",
            triggered_by="seed",
        )
        session.commit()
        job_id = job.id
    finally:
        session.close()

    scan_id = PipelineRunner().run(
        job_id=job_id,
        target_repo="local://demo/vulnerable-app",
        target_branch="main",
        triggered_by="seed",
    )
    print(f"seed_ok scan_id={scan_id} job_id={job_id}")


if __name__ == "__main__":
    main()
