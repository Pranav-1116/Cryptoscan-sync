#!/usr/bin/env python3
"""Run the bundled sample scan so a fresh deploy has inventory to inspect."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
