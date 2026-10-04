from types import SimpleNamespace
from unittest.mock import MagicMock

from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner


def test_gate_stage_persists_decision():
    runner = PipelineRunner()
    ctx = PipelineContext(
        job_id="j1",
        target_repo="local://test-fixture",
        target_branch="main",
        triggered_by="t",
        workspace_dir="/tmp",
        scan_id="s1",
        drift_events=[],
    )
    row = SimpleNamespace(
        id="e1",
        algorithm="DES",
        key_size=None,
        mode="ECB",
        purpose="ENCRYPTION",
        file_path="A.java",
        line_number=1,
        compliance_status="FAIL",
        is_hardcoded_key=False,
        finding_data={"crypto": {"raw_transformation": "DES/ECB/PKCS5Padding"}},
        policy_evaluation={},
    )
    scan = SimpleNamespace(statistics={"total_findings": 1})
    session = MagicMock()
    session.execute.return_value.scalars.return_value = [row]
    session.get.return_value = scan

    runner._gate(ctx, session)

    assert ctx.scan_meta["gate"]["decision"] == "FAIL"
    assert scan.statistics["gate"]["decision"] == "FAIL"
    assert scan.statistics["agility"]["total_sites"] == 1
    session.flush.assert_called()
