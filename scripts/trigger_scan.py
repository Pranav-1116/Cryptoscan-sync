#!/usr/bin/env python3
"""Trigger a scan via the running API or inline pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger a CryptoScan job")
    parser.add_argument("repo_url")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--commit")
    parser.add_argument("--triggered-by", default="manual-cli")
    parser.add_argument("--api", default=os.environ.get("CRYPTOSCAN_API", "http://127.0.0.1:8000"))
    parser.add_argument("--inline", action="store_true", help="Run the pipeline in-process")
    args = parser.parse_args()

    if args.inline:
        from db.connection.session import SessionLocal, init_db
        from db.repositories.job_repository import JobRepository
        from worker.pipeline.pipeline_runner import PipelineRunner

        init_db()
        session = SessionLocal()
        try:
            job = JobRepository(session).create_job(
                job_type="MANUAL",
                target_repo=args.repo_url,
                target_branch=args.branch,
                target_commit=args.commit,
                triggered_by=args.triggered_by,
            )
            session.commit()
            job_id = job.id
        finally:
            session.close()
        scan_id = PipelineRunner().run(
            job_id=job_id,
            target_repo=args.repo_url,
            target_branch=args.branch,
            target_commit=args.commit,
            triggered_by=args.triggered_by,
        )
        print(json.dumps({"job_id": job_id, "scan_id": scan_id}, indent=2))
        return

    import httpx

    login = httpx.post(
        f"{args.api}/api/v1/auth/login",
        json={"username": os.environ.get("ADMIN_USERNAME", "admin"), "password": os.environ.get("ADMIN_PASSWORD", "cryptoscan")},
        timeout=30,
    )
    login.raise_for_status()
    token = login.json()["token"]
    response = httpx.post(
        f"{args.api}/api/v1/scans/trigger",
        json={"repo_url": args.repo_url, "branch": args.branch, "commit": args.commit},
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
