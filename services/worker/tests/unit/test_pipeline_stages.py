from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_language_detect import execute as detect
from worker.pipeline.stage_alert import execute as alert
from worker.pipeline.stage_cbom_generate import execute as cbom


def _ctx(tmp_path) -> PipelineContext:
    return PipelineContext(
        job_id="j1",
        target_repo="local://demo",
        target_branch="main",
        triggered_by="t",
        workspace_dir=str(tmp_path),
        repo_path=str(tmp_path),
        scan_id="s1",
    )


def test_language_detect_stage(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n")
    ctx = detect(_ctx(tmp_path))
    assert "PYTHON" in ctx.scan_meta["languages"]


def test_alert_stage_no_events(tmp_path):
    ctx = alert(_ctx(tmp_path))
    assert ctx.drift_events == []


def test_cbom_stage_writes_file(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.findings = [
        {
            "id": "e1",
            "algorithm": "AES",
            "mode": "GCM",
            "file_path": "a.py",
            "line_number": 1,
        }
    ]
    cbom(ctx)
    assert ctx.scan_meta.get("cbom_path")
