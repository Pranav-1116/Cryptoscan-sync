from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_language_detect import execute as detect
from worker.pipeline.stage_alert import execute as alert
from worker.pipeline.stage_cbom_generate import execute as cbom
from worker.pipeline.stage_cloud_scan import execute as cloud
from worker.pipeline.stage_graph_sync import execute as graph_sync
from worker.pipeline.stage_network_scan import execute as tls


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


def test_cloud_and_tls_stages(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" { bucket = "x" }\n')
    (tmp_path / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\nspec:\n  tls:\n    - hosts: [\"web.example.com\"]\n  rules:\n    - host: web.example.com\n"
    )
    ctx = cloud(_ctx(tmp_path))
    ctx = tls(ctx)
    assert ctx.scan_meta.get("cloud", {}).get("resources", 0) >= 1
    assert ctx.scan_meta.get("tls", {}).get("targets", 0) >= 1


def test_graph_sync_stage_fail_open(tmp_path):
    ctx = graph_sync(_ctx(tmp_path), session=None)
    assert ctx.job_id == "j1"


def test_scan_stage_carries_cascade_and_inventory_fields(tmp_path):
    from worker.pipeline.stage_scan import execute as scan

    (tmp_path / "util").mkdir()
    (tmp_path / "util" / "crypto.py").write_text("import hashlib\ndef h(b):\n    return hashlib.sha256(b).hexdigest()\n")
    (tmp_path / "app.py").write_text("from util.crypto import h\n")
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.5\n")
    ctx = scan(_ctx(tmp_path))
    stats = ctx.scan_meta["statistics"]
    cascade = stats["cascade"]
    assert stats["cascade_providers"] == 1 and cascade["providers"][0]["file"] == "util/crypto.py" and cascade["providers"][0]["direct_dependents"] == 1
    assert [l["library"] for l in cascade["libraries"] if l["manifests"]] == ["python-cryptography"]
    assert cascade["truncated"]["providers"] == 0
    assert all(isinstance(f, dict) and f["metadata"].get("code_origin") for f in ctx.findings)  # findings travel as JSON dicts
