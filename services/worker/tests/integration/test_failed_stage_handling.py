"""Pipeline marks the failed stage and re-raises a wrapped error."""

from unittest.mock import patch

import pytest

from worker.pipeline.pipeline_runner import PipelineRunner


def test_failed_scan_stage_is_wrapped(temp_workspace, test_db, mock_scan_job):
    runner = PipelineRunner()
    with patch("worker.workspace.repo_cloner.RepoCloner.clone") as mock_clone:
        mock_clone.return_value = temp_workspace / "repo"
        (temp_workspace / "repo").mkdir()
        with patch("scanner.core.scanner.Scanner.scan", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError, match="Pipeline failed at stage scan"):
                runner.run(job=mock_scan_job, workspace=temp_workspace, db=test_db)
