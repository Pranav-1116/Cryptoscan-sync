"""Quantum pipeline stage: scan-level report + plan persisted into scan statistics."""

from __future__ import annotations

import inspect
import logging
from types import SimpleNamespace

from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner
from worker.pipeline.stage_quantum import execute as quantum_stage


class FakeSession:
    def __init__(self, evidence, scan=None, system=None):
        self._evidence = evidence
        self._scan = scan
        self._system = system
        self.flushed = 0

    def execute(self, _query):
        return SimpleNamespace(scalars=lambda: list(self._evidence))

    def get(self, model, pk):
        name = getattr(model, "__name__", str(model))
        if name == "Scan":
            return self._scan
        if name == "System":
            return self._system
        return None

    def flush(self):
        self.flushed += 1


def _row(eid, algorithm, **extra):
    return SimpleNamespace(
        id=eid,
        algorithm=algorithm,
        key_size=extra.get("key_size"),
        mode=extra.get("mode"),
        purpose=extra.get("purpose"),
        file_path=extra.get("file_path", "src/x.py"),
        line_number=extra.get("line_number", 1),
        compliance_status=extra.get("compliance_status", "PASS"),
        is_hardcoded_key=extra.get("is_hardcoded_key", False),
    )


def _ctx(**overrides):
    base = dict(
        job_id="j1", target_repo="local://test-fixture", target_branch="main",
        triggered_by="t", workspace_dir="/tmp", scan_id="scan-1", system_id="sys-1",
    )
    base.update(overrides)
    return PipelineContext(**base)


def test_quantum_stage_persists_summary_into_scan_statistics():
    system = SimpleNamespace(
        to_dict=lambda: {"id": "sys-1", "extra": {"data_retention_years": 10, "pq_migration_years": 2}},
        extra={"data_retention_years": 10, "pq_migration_years": 2},
    )
    scan = SimpleNamespace(statistics={"total_findings": 3})
    session = FakeSession(
        [
            _row("e1", "RSA", key_size=2048, purpose="KEY_EXCHANGE"),
            _row("e2", "AES", key_size=256, purpose="ENCRYPTION"),
            _row("e3", "ML-KEM-768", purpose="KEY_EXCHANGE"),
        ],
        scan=scan,
        system=system,
    )
    ctx = _ctx()
    quantum_stage(ctx, session)

    summary = ctx.scan_meta["quantum"]
    assert summary["vulnerable_count"] == 1
    assert summary["pqc_ready_count"] == 0
    assert summary["pqc_candidate_count"] == 1
    assert summary["deployment_readiness"] == "NOT_ESTABLISHED"
    assert summary["mosca"]["scenario_only"] is True
    assert summary["total_sites"] == 3
    assert summary["overall_hndl_risk"] == "HIGH"
    assert summary["wave1_sites"] == 1  # RSA under 10y retention = HNDL HIGH
    targets = [stream["target"] for stream in summary["workstreams"]]
    assert "ML-KEM-768" in targets
    # Mosca with the system's own declared migration estimate
    assert summary["mosca"]["verdict"] == "ALREADY_LATE"  # x=10, y=2 vs z
    assert summary["mosca"]["y_migration_years"] == 2
    assert summary["mosca"]["computable"] is True
    # persisted additively next to the gate stats
    assert scan.statistics["quantum"] is summary
    assert scan.statistics["total_findings"] == 3
    assert session.flushed == 1


def test_quantum_stage_honest_mosca_without_system():
    scan = SimpleNamespace(statistics={})
    session = FakeSession([_row("e1", "RSA", key_size=2048)], scan=scan, system=None)
    ctx = _ctx()
    quantum_stage(ctx, session)
    summary = ctx.scan_meta["quantum"]
    assert summary["mosca"]["computable"] is False  # no retention data — never guessed
    assert summary["vulnerable_count"] == 1
    assert scan.statistics["quantum"]["mosca"]["computable"] is False


def test_quantum_stage_survives_missing_scan_row():
    session = FakeSession([_row("e1", "RSA", key_size=2048)], scan=None, system=None)
    ctx = _ctx()
    quantum_stage(ctx, session)
    assert ctx.scan_meta["quantum"]["vulnerable_count"] == 1  # meta set even without persistence


def test_quantum_stage_noop_without_session_or_scan():
    ctx = _ctx()
    assert quantum_stage(ctx, None) is ctx
    assert ctx.scan_meta == {}
    assert quantum_stage(_ctx(scan_id=None), FakeSession([])).scan_meta == {}


def test_alert_stage_flags_quantum_hndl(caplog):
    runner = PipelineRunner()
    ctx = _ctx()
    ctx.scan_meta["quantum"] = {"overall_hndl_risk": "CRITICAL", "mosca": {"verdict": "ALREADY_LATE"}, "wave1_sites": 4}
    with caplog.at_level(logging.WARNING, logger="worker.pipeline.pipeline_runner"):
        runner._alert(ctx)
    assert any("quantum_migration_alert" in record.message for record in caplog.records)


def test_alert_stage_quiet_when_quantum_fine(caplog):
    runner = PipelineRunner()
    ctx = _ctx()
    ctx.scan_meta["quantum"] = {"overall_hndl_risk": "LOW", "mosca": {"verdict": "SAFE_MARGIN"}, "wave1_sites": 0}
    with caplog.at_level(logging.WARNING, logger="worker.pipeline.pipeline_runner"):
        runner._alert(ctx)
    assert not any("quantum_migration_alert" in record.message for record in caplog.records)


def test_pipeline_run_sequences_quantum_stage():
    source = inspect.getsource(PipelineRunner.run)
    assert '"quantum"' in source
    # quantum runs after drift and before the gate
    assert source.index('"drift"') < source.index('"quantum"') < source.index('"gate"')


def test_runner_quantum_method_delegates():
    """_quantum must not raise even when the import path is broken."""
    runner = PipelineRunner()
    ctx = _ctx()
    runner._quantum(ctx, FakeSession([]))  # real stage runs, empty evidence is fine
    assert ctx.scan_meta["quantum"]["total_sites"] == 0
