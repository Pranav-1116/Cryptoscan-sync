from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_cert_inventory import execute as cert_inventory
from worker.pipeline.stage_multi_scanner import execute as multi


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


def test_cert_inventory_stage_merges(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.tls_result = {
        "certificates": [
            {"fingerprint_sha256": "abc", "days_until_expiry": 6, "subject": "CN=api", "usages": ["tls://a"]},
            {"fingerprint_sha256": "abc", "endpoint": "tls://b", "days_until_expiry": 5},
        ]
    }
    cert_inventory(ctx)
    assert ctx.scan_meta["certs"]["count"] == 1
    assert ctx.scan_meta["certs"]["alerts"] == 1


def test_multi_scanner_stage_runs_cloud(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" { bucket = "x" }\n')
    ctx = multi(_ctx(tmp_path))
    assert ctx.scan_meta.get("cloud", {}).get("resources", 0) >= 1
