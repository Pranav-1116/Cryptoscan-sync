from unittest.mock import patch

import pytest

from worker.pipeline.pipeline_runner import PipelineRunner


def test_pipeline_wraps_scan_failure(temp_workspace, test_db, mock_scan_job):
    with patch("worker.workspace.repo_cloner.RepoCloner.clone") as mock_clone:
        mock_clone.return_value = temp_workspace / "repo"
        (temp_workspace / "repo").mkdir()
        with patch("scanner.core.scanner.Scanner.scan", side_effect=RuntimeError("scanner crashed")):
            with pytest.raises(RuntimeError, match="Pipeline failed at stage"):
                PipelineRunner().run(job=mock_scan_job, workspace=temp_workspace, db=test_db)
