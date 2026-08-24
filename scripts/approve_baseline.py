#!/usr/bin/env python3
"""
CLI Script: Approve Baseline
Approves a scan as baseline for drift detection
"""
import sys
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db.connection.session import SessionLocal
from database.db.repositories.baseline_repository import BaselineRepository
from database.db.repositories.scan_repository import ScanRepository
from shared_logging.logger_factory import create_logger

logger = create_logger("approve-baseline", json_format=False)


def approve_baseline(
    scan_id: str,
    system_identifier: str,
    environment: str,
    approved_by: str,
    notes: str = None
):
    """
    Approve a scan as baseline
    """
    db = SessionLocal()
    
    try:
        # Verify scan exists
        scan_repo = ScanRepository(db)
        scan = scan_repo.get_by_id(scan_id)
        
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            sys.exit(1)
        
        logger.info(f"Found scan: {scan_id}")
        logger.info(f"  Target: {scan.target_location}")
        logger.info(f"  Branch: {scan.target_branch}")
        logger.info(f"  Commit: {scan.target_commit}")
        logger.info(f"  Findings: {scan.statistics.get('total_findings', 'unknown')}")
        
        # Create baseline
        baseline_repo = BaselineRepository(db)
        baseline = baseline_repo.create(
            system_identifier=system_identifier,
            environment=environment,
            approved_scan_id=scan_id,
            approved_by=approved_by,
            notes=notes
        )
        
        logger.info(f"✅ Baseline created: {baseline.baseline_id}")
        logger.info(f"   System: {system_identifier}")
        logger.info(f"   Environment: {environment}")
        logger.info(f"   Approved by: {approved_by}")
        
        if notes:
            logger.info(f"   Notes: {notes}")
        
        print(f"\nBaseline ID: {baseline.baseline_id}")
        
    except Exception as e:
        logger.error(f"Failed to approve baseline: {e}", exc_info=True)
        sys.exit(1)
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Approve a scan as baseline for drift detection"
    )
    parser.add_argument(
        "scan_id",
        help="Scan ID to approve as baseline"
    )
    parser.add_argument(
        "--system",
        required=True,
        help="System identifier (e.g., repository URL)"
    )
    parser.add_argument(
        "--environment",
        default="prod",
        choices=["prod", "staging", "dev"],
        help="Environment (default: prod)"
    )
    parser.add_argument(
        "--approved-by",
        required=True,
        help="Name of person approving baseline"
    )
    parser.add_argument(
        "--notes",
        help="Optional notes about this baseline"
    )
    
    args = parser.parse_args()
    
    approve_baseline(
        scan_id=args.scan_id,
        system_identifier=args.system,
        environment=args.environment,
        approved_by=args.approved_by,
        notes=args.notes
    )


if __name__ == "__main__":
    main()