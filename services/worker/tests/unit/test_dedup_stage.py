"""Dedup stage wiring: canonical merge + stats persisted onto the scan."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import sqlalchemy.orm.attributes as sa_attrs

from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner


def _row(row_id, algorithm, finding_data, **columns):
    return SimpleNamespace(
        id=row_id,
        algorithm=algorithm,
        key_size=columns.get("key_size"),
        mode=columns.get("mode"),
        purpose=columns.get("purpose", "KEY_EXCHANGE"),
        file_path=columns.get("file_path", "Pay.java"),
        line_number=columns.get("line_number", 10),
        compliance_status="FAIL",
        is_hardcoded_key=False,
        confidence=columns.get("confidence", "HIGH"),
        finding_data=finding_data,
        policy_evaluation={},
    )


def test_dedup_stage_collapses_and_persists_stats(monkeypatch):
    runner = PipelineRunner()
    runner._link_system_assets = lambda ctx, session, stored: None
    runner._quantum_assets = lambda ctx, session, stored: None
    ctx = PipelineContext(
        job_id="j1",
        target_repo="local://test-fixture",
        target_branch="main",
        triggered_by="t",
        workspace_dir="/tmp",
        scan_id="s1",
    )
    rows = [
        # same RSA-2048 key exchange, two scanners, two name spellings
        _row("e1", "RSA-2048", {"scanner_id": "static-java-scanner-v1.0", "confidence": "HIGH"}),
        _row("e2", "rsa_2048", {"scanner_id": "static-python-scanner-v1.0", "confidence": "MEDIUM"}),
        # a genuinely different asset
        _row("e3", "AES-256-GCM", {"scanner_id": "static-java-scanner-v1.0", "confidence": "HIGH"}, purpose="ENCRYPTION", line_number=40),
    ]
    scan = SimpleNamespace(statistics={"total_findings": 3})
    session = MagicMock()
    session.execute.return_value.scalars.return_value = []  # no existing assets
    session.get.return_value = scan
    flag_calls = []
    monkeypatch.setattr(sa_attrs, "flag_modified", lambda *args: flag_calls.append(args))

    runner._dedup(ctx, session, rows)

    stats = ctx.scan_meta["dedup"]
    assert stats["identity_mode"] == "canonical"
    assert stats["findings_in"] == 3
    assert stats["assets_out"] == 2
    assert stats["duplicate_findings_collapsed"] == 1
    assert stats["multi_scanner_groups"] == 1
    assert stats["verified_assets"] == 1
    # stats land on scan.statistics and the mutation is flagged for the ORM
    assert scan.statistics["dedup"] is stats
    assert scan.statistics["total_findings"] == 3  # additive, nothing clobbered
    assert flag_calls == [(scan, "statistics")]
    session.flush.assert_called()


def test_dedup_stage_no_duplicates_is_not_verified(monkeypatch):
    runner = PipelineRunner()
    runner._link_system_assets = lambda ctx, session, stored: None
    runner._quantum_assets = lambda ctx, session, stored: None
    ctx = PipelineContext(
        job_id="j2",
        target_repo="local://test-fixture",
        target_branch="main",
        triggered_by="t",
        workspace_dir="/tmp",
        scan_id="s2",
    )
    rows = [_row("e1", "DES", {"scanner_id": "static-java-scanner-v1.0"}, purpose="ENCRYPTION")]
    scan = SimpleNamespace(statistics=None)
    session = MagicMock()
    session.execute.return_value.scalars.return_value = []
    session.get.return_value = scan
    monkeypatch.setattr(sa_attrs, "flag_modified", lambda *args: None)

    runner._dedup(ctx, session, rows)

    stats = scan.statistics["dedup"]
    assert stats["duplicate_findings_collapsed"] == 0
    assert stats["cross_scanner_verification_rate"] == 0.0
    assert stats["collapse_rate"] == 0.0
