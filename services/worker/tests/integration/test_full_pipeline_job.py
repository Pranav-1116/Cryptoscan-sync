"""
Integration Test: Full Pipeline Execution
"""
import pytest
from unittest.mock import patch

from worker.pipeline.pipeline_runner import PipelineRunner


@pytest.mark.integration
def test_full_pipeline_execution(test_db, temp_workspace, mock_scan_job):
    """
    Test full pipeline execution
    Mocks: Git clone, Scanner
    Real: Evidence, DB, Normalization, Policy
    """
    runner = PipelineRunner()
    
    # Mock git clone
    with patch('worker.workspace.repo_cloner.RepoCloner.clone') as mock_clone:
        mock_clone.return_value = temp_workspace / "repo"
        (temp_workspace / "repo").mkdir()
        
        # Mock scanner
        with patch('scanner.core.scanner.Scanner.scan') as mock_scan:
            from scanner.models.scan_result import ScanResult, ScanStatistics
            from scanner.models.raw_finding import RawFinding

            result = ScanResult(
                findings=[
                    RawFinding(
                        algorithm="DES",
                        file_path="Payment.java",
                        line_number=247,
                        confidence="HIGH"
                    )
                ],
            )
            result.statistics = ScanStatistics(files_scanned=100, duration_seconds=5.2)
            result.finalize()
            mock_scan.return_value = result
            
            # Execute pipeline
            context = {
                "job": mock_scan_job,
                "workspace": temp_workspace,
                "db": test_db
            }
            
            scan_id = runner.run(
                job=mock_scan_job,
                workspace=temp_workspace,
                db=test_db
            )
            
            # Verify scan created
            assert scan_id is not None
            
            # Verify evidence in DB
            from db.repositories.evidence_repository import EvidenceRepository
            evidence_repo = EvidenceRepository(test_db)
            
            evidence_records = evidence_repo.get_by_scan(scan_id)
            assert len(evidence_records) == 1
            assert evidence_records[0].algorithm == "DES"


@pytest.mark.integration
def test_pipeline_failure_handling(test_db, temp_workspace, mock_scan_job):
    """
    Test pipeline handles stage failures gracefully
    """
    runner = PipelineRunner()
    
    # Mock scanner to raise exception
    with patch('scanner.core.scanner.Scanner.scan') as mock_scan:
        mock_scan.side_effect = RuntimeError("Scanner crashed")
        
        # Mock clone to succeed
        with patch('worker.workspace.repo_cloner.RepoCloner.clone') as mock_clone:
            mock_clone.return_value = temp_workspace / "repo"
            (temp_workspace / "repo").mkdir()
            
            # Execute pipeline - should raise
            with pytest.raises(RuntimeError, match="Pipeline failed at stage"):
                runner.run(
                    job=mock_scan_job,
                    workspace=temp_workspace,
                    db=test_db
                )