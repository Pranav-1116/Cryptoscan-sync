from worker.pipeline.pipeline_runner import PipelineContext


def test_context_update():
    ctx = PipelineContext(
        job_id="j",
        target_repo="local://test-fixture",
        target_branch="main",
        triggered_by="t",
        workspace_dir="/tmp",
    )
    ctx.update(repo_path="/tmp/repo")
    assert ctx.repo_path == "/tmp/repo"
