"""
Main pipeline orchestrator.
Runs all 8 stages in sequence with error handling and progress tracking.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from worker.config.settings import get_settings
from worker.pipeline.stage_alert import StageAlert
from worker.pipeline.stage_clone import StageClone
from worker.pipeline.stage_drift import StageDrift
from worker.pipeline.stage_evidence import StageEvidence
from worker.pipeline.stage_load import StageLoad
from worker.pipeline.stage_normalize import StageNormalize
from worker.pipeline.stage_policy import StagePolicy
from worker.pipeline.stage_scan import StageScan

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass(frozen=True)
class PipelineContext:
    """Immutable context passed through all pipeline stages."""

    job_id: str
    scan_id: Optional[str]
    target_repo: str
    target_branch: str
    target_commit: Optional[str]
    triggered_by: str
    workspace_dir: str
    repo_path: str
    scan_results_file: Optional[str] = None
    evidence_records_file: Optional[str] = None
    baseline_id: Optional[str] = None
    drift_events: Optional[list[Dict[str, Any]]] = None

    def update(self, **kwargs) -> PipelineContext:
        """Create new context with updated fields (functional style)."""
        return PipelineContext(
            job_id=kwargs.get("job_id", self.job_id),
            scan_id=kwargs.get("scan_id", self.scan_id),
            target_repo=kwargs.get("target_repo", self.target_repo),
            target_branch=kwargs.get("target_branch", self.target_branch),
            target_commit=kwargs.get("target_commit", self.target_commit),
            triggered_by=kwargs.get("triggered_by", self.triggered_by),
            workspace_dir=kwargs.get("workspace_dir", self.workspace_dir),
            repo_path=kwargs.get("repo_path", self.repo_path),
            scan_results_file=kwargs.get("scan_results_file", self.scan_results_file),
            evidence_records_file=kwargs.get(
                "evidence_records_file", self.evidence_records_file
            ),
            baseline_id=kwargs.get("baseline_id", self.baseline_id),
            drift_events=kwargs.get("drift_events", self.drift_events),
        )


class PipelineStageError(Exception):
    """Raised when a pipeline stage fails."""

    def __init__(self, stage_name: str, error: Exception):
        self.stage_name = stage_name
        self.error = error
        super().__init__(f"Stage '{stage_name}' failed: {str(error)}")


class PipelineRunner:
    """
    Orchestrates the full 8-stage scanning pipeline.

    Stages:
    1. Clone: Git clone repo to workspace
    2. Scan: Run static scanner, produce findings
    3. Evidence: Hash findings, create integrity chain
    4. Load: Persist evidence to database
    5. Normalize: Canonicalise algorithm names
    6. Policy: Evaluate compliance rules
    7. Drift: Detect changes from baseline
    8. Alert: Send notifications (if needed)
    """

    def __init__(self):
        self.stage_clone = StageClone()
        self.stage_scan = StageScan()
        self.stage_evidence = StageEvidence()
        self.stage_load = StageLoad()
        self.stage_normalize = StageNormalize()
        self.stage_policy = StagePolicy()
        self.stage_drift = StageDrift()
        self.stage_alert = StageAlert()

    async def run(
        self,
        job_id: str,
        target_repo: str,
        target_branch: str,
        target_commit: Optional[str],
        triggered_by: str,
        workspace_dir: str,
    ) -> Dict[str, Any]:
        """
        Execute the full pipeline.

        Returns: {
            'success': bool,
            'scan_id': str or None,
            'evidence_count': int or None,
            'compliant': int,
            'non_compliant': int,
            'drift_events': list[dict],
            'error': str or None,
        }
        """
        ctx = PipelineContext(
            job_id=job_id,
            scan_id=None,
            target_repo=target_repo,
            target_branch=target_branch,
            target_commit=target_commit,
            triggered_by=triggered_by,
            workspace_dir=workspace_dir,
            repo_path="",
        )

        logger.info(
            "pipeline_start",
            extra={
                "job_id": job_id,
                "repo": target_repo,
                "branch": target_branch,
            },
        )

        result = {
            "success": False,
            "scan_id": None,
            "evidence_count": None,
            "compliant": 0,
            "non_compliant": 0,
            "drift_events": [],
            "error": None,
        }

        stages = [
            ("clone", self.stage_clone),
            ("scan", self.stage_scan),
            ("evidence", self.stage_evidence),
            ("load", self.stage_load),
            ("normalize", self.stage_normalize),
            ("policy", self.stage_policy),
            ("drift", self.stage_drift),
            ("alert", self.stage_alert),
        ]

        try:
            for stage_idx, (stage_name, stage_handler) in enumerate(stages):
                logger.info(
                    "stage_start",
                    extra={"job_id": job_id, "stage": stage_name, "index": stage_idx},
                )

                try:
                    ctx = await stage_handler.execute(ctx)
                    logger.info(
                        "stage_complete",
                        extra={
                            "job_id": job_id,
                            "stage": stage_name,
                            "index": stage_idx,
                        },
                    )
                except Exception as exc:
                    logger.exception(
                        "stage_failed",
                        extra={
                            "job_id": job_id,
                            "stage": stage_name,
                            "error": str(exc),
                        },
                    )
                    raise PipelineStageError(stage_name, exc)

            # SUCCESS
            result["success"] = True
            result["scan_id"] = ctx.scan_id
            result["drift_events"] = ctx.drift_events or []

            logger.info(
                "pipeline_complete",
                extra={
                    "job_id": job_id,
                    "scan_id": ctx.scan_id,
                    "success": True,
                },
            )

        except PipelineStageError as exc:
            result["error"] = str(exc)
            logger.exception(
                "pipeline_failed",
                extra={"job_id": job_id, "stage": exc.stage_name},
            )

        except Exception as exc:
            result["error"] = f"Unexpected error: {str(exc)}"
            logger.exception("pipeline_unexpected_error", extra={"job_id": job_id})

        finally:
            # Cleanup workspace (optional — can be disabled for debugging)
            if settings.CLEANUP_WORKSPACE:
                logger.debug("cleanup_workspace", extra={"job_id": job_id})

        return result