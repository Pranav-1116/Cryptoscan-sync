# services/worker/worker/core/job_executor.py

"""
Production job executor with full pipeline orchestration.
Manages scan lifecycle: clone → scan → evidence → load → normalize → policy → drift → alert
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum
import traceback

logger = logging.getLogger(__name__)


class PipelineStage(str, Enum):
    """Pipeline execution stages."""
    CLONE = "CLONE"
    SCAN = "SCAN"
    EVIDENCE = "EVIDENCE"
    LOAD = "LOAD"
    NORMALIZE = "NORMALIZE"
    POLICY = "POLICY"
    DRIFT = "DRIFT"
    ALERT = "ALERT"


@dataclass
class StageResult:
    """Result of a pipeline stage execution."""
    stage: PipelineStage
    success: bool
    duration_seconds: float
    error: Optional[str] = None
    output_data: Optional[Dict[str, Any]] = None


@dataclass
class PipelineContext:
    """
    Context data passed through all pipeline stages.
    Accumulates results and shared state.
    """
    job_id: str
    scan_id: str
    target_repo: str
    target_commit: str
    target_branch: str
    triggered_by: str
    
    # Stage outputs (populated as pipeline progresses)
    workspace_path: Optional[str] = None
    raw_findings: Optional[list] = None
    evidence_records: Optional[list] = None
    normalized_findings: Optional[list] = None
    policy_results: Optional[Dict[str, Any]] = None
    drift_summary: Optional[Dict[str, Any]] = None
    
    # Execution tracking
    stage_results: Dict[PipelineStage, StageResult] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.stage_results is None:
            self.stage_results = {}
        if self.started_at is None:
            self.started_at = datetime.utcnow()
    
    @property
    def total_duration_seconds(self) -> float:
        """Calculate total execution time."""
        if self.completed_at is None:
            return 0
        return (self.completed_at - self.started_at).total_seconds()
    
    @property
    def failed_stages(self) -> list:
        """Get list of failed stages."""
        return [
            stage for stage, result in self.stage_results.items()
            if not result.success
        ]
    
    def record_stage_result(self, result: StageResult) -> None:
        """Record stage execution result."""
        self.stage_results[result.stage] = result
        logger.info(
            f"Stage {result.stage.value} completed: "
            f"success={result.success}, duration={result.duration_seconds:.2f}s"
        )


class JobExecutor:
    """
    Production job executor with full error handling, retries, and monitoring.
    Coordinates all pipeline stages in sequence.
    """
    
    def __init__(
        self,
        clone_stage,
        scan_stage,
        evidence_stage,
        load_stage,
        normalize_stage,
        policy_stage,
        drift_stage,
        alert_stage,
        database_service,
        workspace_manager,
    ):
        """
        Initialize executor with injected pipeline stages.
        
        Args:
            clone_stage: CloneStage instance
            scan_stage: ScanStage instance
            evidence_stage: EvidenceStage instance
            load_stage: LoadStage instance
            normalize_stage: NormalizeStage instance
            policy_stage: PolicyStage instance
            drift_stage: DriftStage instance
            alert_stage: AlertStage instance
            database_service: Database repository service
            workspace_manager: Workspace manager for temp directories
        """
        self.clone_stage = clone_stage
        self.scan_stage = scan_stage
        self.evidence_stage = evidence_stage
        self.load_stage = load_stage
        self.normalize_stage = normalize_stage
        self.policy_stage = policy_stage
        self.drift_stage = drift_stage
        self.alert_stage = alert_stage
        self.database_service = database_service
        self.workspace_manager = workspace_manager
        
        # Stage execution order
        self.pipeline_stages = [
            (PipelineStage.CLONE, self.clone_stage),
            (PipelineStage.SCAN, self.scan_stage),
            (PipelineStage.EVIDENCE, self.evidence_stage),
            (PipelineStage.LOAD, self.load_stage),
            (PipelineStage.NORMALIZE, self.normalize_stage),
            (PipelineStage.POLICY, self.policy_stage),
            (PipelineStage.DRIFT, self.drift_stage),
            (PipelineStage.ALERT, self.alert_stage),
        ]
    
    async def execute_job(self, job) -> bool:
        """
        Execute complete scan job pipeline.
        
        Args:
            job: ScanJob object from queue
        
        Returns:
            True if all stages succeeded, False otherwise
        """
        # Create pipeline context
        context = PipelineContext(
            job_id=job.job_id,
            scan_id=job.scan_id,
            target_repo=job.target_repo,
            target_commit=job.target_commit,
            target_branch=job.target_branch,
            triggered_by=job.triggered_by,
        )
        
        logger.info(
            f"Starting job execution: {job.job_id} "
            f"(scan: {job.scan_id}, repo: {job.target_repo})"
        )
        
        try:
            # Update scan status to RUNNING
            await self.database_service.mark_scan_running(job.scan_id)
            
            # Execute pipeline stages sequentially
            for stage_name, stage_executor in self.pipeline_stages:
                try:
                    logger.info(f"Executing stage: {stage_name.value}")
                    
                    stage_start = datetime.utcnow()
                    
                    # Execute stage (stages are async)
                    stage_result = await stage_executor.execute(context)
                    
                    stage_duration = (datetime.utcnow() - stage_start).total_seconds()
                    
                    if not stage_result.success:
                        logger.error(
                            f"Stage {stage_name.value} failed: {stage_result.error}"
                        )
                        context.record_stage_result(StageResult(
                            stage=stage_name,
                            success=False,
                            duration_seconds=stage_duration,
                            error=stage_result.error,
                        ))
                        
                        # Stop pipeline on stage failure
                        break
                    
                    # Record stage success
                    context.record_stage_result(StageResult(
                        stage=stage_name,
                        success=True,
                        duration_seconds=stage_duration,
                        output_data=stage_result.output_data,
                    ))
                
                except Exception as e:
                    logger.exception(
                        f"Stage {stage_name.value} exception: {e}"
                    )
                    context.record_stage_result(StageResult(
                        stage=stage_name,
                        success=False,
                        duration_seconds=(datetime.utcnow() - stage_start).total_seconds(),
                        error=traceback.format_exc(),
                    ))
                    break
            
            # Determine overall success
            context.completed_at = datetime.utcnow()
            
            if len(context.failed_stages) == 0:
                # All stages succeeded
                logger.info(
                    f"Job completed successfully: {job.job_id} "
                    f"(duration: {context.total_duration_seconds:.2f}s)"
                )
                await self.database_service.mark_scan_completed(
                    job.scan_id,
                    context.stage_results,
                )
                return True
            else:
                # Pipeline failed
                failed_stage = context.failed_stages[0]
                error_msg = (
                    context.stage_results[failed_stage].error or "Unknown error"
                )
                
                logger.error(
                    f"Job failed at stage {failed_stage.value}: {error_msg}"
                )
                await self.database_service.mark_scan_failed(
                    job.scan_id,
                    f"Pipeline failed at {failed_stage.value}: {error_msg}",
                    context.stage_results,
                )
                return False
        
        except Exception as e:
            # Unexpected error (not in stage execution)
            logger.exception(f"Job execution failed: {e}")
            
            context.completed_at = datetime.utcnow()
            
            try:
                await self.database_service.mark_scan_failed(
                    job.scan_id,
                    f"Job executor error: {str(e)}",
                    context.stage_results,
                )
            except Exception as db_error:
                logger.exception(f"Failed to mark scan as failed: {db_error}")
            
            return False
        
        finally:
            # Cleanup workspace
            if context.workspace_path:
                try:
                    await self.workspace_manager.cleanup(context.workspace_path)
                except Exception as e:
                    logger.warning(f"Workspace cleanup error: {e}")
    
    async def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """
        Get current job execution status.
        
        Args:
            job_id: Job identifier
        
        Returns:
            Status dictionary with stage progress
        """
        # Query from database or cache
        return await self.database_service.get_job_status(job_id)