#!/usr/bin/env python3
"""
CLI Script: Trigger Manual Scan
Triggers a scan job and queues it
"""
import sys
import argparse
import uuid
import json
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db.connection.session import SessionLocal
from database.db.repositories.job_repository import JobRepository
from worker.core.job_consumer import JobConsumer, ScanJob
from shared_logging.logger_factory import create_logger
from api.config.settings import Settings

logger = create_logger("trigger-scan", json_format=False)


def trigger_scan(
    repo_url: str,
    branch: str,
    commit: str = None,
    triggered_by: str = "manual-cli"
):
    """
    Trigger a scan job
    """
    settings = Settings()
    db = SessionLocal()
    
    try:
        # Generate job ID
        job_id = str(uuid.uuid4())
        
        # Create job record
        job_repo = JobRepository(db)
        job = job_repo.create(
            job_id=job_id,
            job_type="MANUAL",
            target_repo=repo_url,
            target_branch=branch,
            target_commit=commit,
            triggered_by=triggered_by
        )
        
        logger.info(f"Created scan job: {job_id}")
        
        # Queue job
        consumer = JobConsumer(
            redis_url=settings.REDIS_URL,
            queue_name="scan-jobs"
        )
        
        scan_job = ScanJob(
            job_id=job_id,
            job_type="MANUAL",
            target_repo=repo_url,
            target_commit=commit,
            target_branch=branch,
            triggered_by=triggered_by,
            created_at=datetime.utcnow().isoformat()
        )
        
        success = consumer.publish_job(scan_job)
        
        if success:
            logger.info(f"✅ Job queued successfully")
            logger.info(f"   Job ID: {job_id}")
            logger.info(f"   Repository: {repo_url}")
            logger.info(f"   Branch: {branch}")
            if commit:
                logger.info(f"   Commit: {commit}")
            
            print(f"\nJob ID: {job_id}")
            print(f"Monitor status: GET /api/jobs/{job_id}")
        else:
            logger.error("Failed to queue job")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"Failed to trigger scan: {e}", exc_info=True)
        sys.exit(1)
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Trigger a manual scan job"
    )
    parser.add_argument(
        "repo_url",
        help="Repository URL to scan"
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to scan (default: main)"
    )
    parser.add_argument(
        "--commit",
        help="Specific commit to scan (default: HEAD of branch)"
    )
    parser.add_argument(
        "--triggered-by",
        default="manual-cli",
        help="Who triggered this scan (default: manual-cli)"
    )
    
    args = parser.parse_args()
    
    trigger_scan(
        repo_url=args.repo_url,
        branch=args.branch,
        commit=args.commit,
        triggered_by=args.triggered_by
    )


if __name__ == "__main__":
    main()