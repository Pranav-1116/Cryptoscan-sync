from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_ot_scan import execute as ot_scan


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


def test_ot_stage_adds_findings_without_sending(tmp_path):
    (tmp_path / "opcua.log").write_text(
        "src=10.0.2.15 dst=10.0.2.1 port=4840 security_mode=None product=Siemens\n"
    )
    ctx = ot_scan(_ctx(tmp_path))
    assert ctx.scan_meta["ot"]["packets_sent"] == 0
    assert ctx.findings
    assert ctx.ot_result["device_count"] >= 1
