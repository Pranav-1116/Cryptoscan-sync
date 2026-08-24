"""
Pipeline Stage 2: Static code scanning.
Runs the crypto scanner on the cloned repository.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from scanner.core.scanner import Scanner
from scanner.config.scanner_config import ScannerConfig

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


class StageScan:
    """Scan stage: run static scanner."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        Run scanner on cloned repo.
        Output: scan-results-{timestamp}.json

        Returns: Updated context with scan_results_file path.
        """
        logger.info(
            "scan_start",
            extra={
                "job_id": ctx.job_id,
                "repo_path": ctx.repo_path,
            },
        )

        try:
            scanner_config = ScannerConfig(
                source_dir=ctx.repo_path,
                exclude_dirs=["node_modules", ".git", "test", "tests", ".venv"],
                include_languages=["java", "python", "go", "rust", "javascript"],
            )

            scanner = Scanner(config=scanner_config)
            scan_result = await scanner.scan()

            # Write findings to JSON
            output_file = Path(ctx.workspace_dir) / f"scan-results-{ctx.job_id}.json"
            with open(output_file, "w") as f:
                json.dump(scan_result.model_dump(), f, indent=2)

            logger.info(
                "scan_complete",
                extra={
                    "job_id": ctx.job_id,
                    "findings_count": scan_result.statistics.total_findings,
                    "files_scanned": scan_result.statistics.files_scanned,
                    "output": str(output_file),
                },
            )

            return ctx.update(scan_results_file=str(output_file))

        except Exception as exc:
            logger.exception(
                "scan_failed",
                extra={
                    "job_id": ctx.job_id,
                    "error": str(exc),
                },
            )
            raise