"""§4.8 (round 39): a COMPLETED scan must disclose soft-failed optional
derived/provider stages instead of implying complete observation.

The pipeline runner records every soft skip (optional collector import
failure, persist skip, alert failure) into scan statistics under
``optional_stage_failures``; the scan list UI surfaces it as an amber
"observation incomplete" marker rather than letting COMPLETED imply
full coverage.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner


def _ctx(**overrides) -> PipelineContext:
    base = dict(
        job_id="j1", target_repo="local://test-fixture", target_branch="main",
        triggered_by="t", workspace_dir="/tmp", scan_id="scan-1", system_id="sys-1",
    )
    base.update(overrides)
    return PipelineContext(**base)


class _Result:
    def __init__(self, scan):
        self._scan = scan

    def scalar_one_or_none(self):
        return self._scan


class FakeSession:
    def __init__(self, scan=None):
        self._scan = scan

    def execute(self, _query):
        return _Result(self._scan)


def test_optional_failure_lands_in_scan_meta_statistics():
    runner = PipelineRunner()
    ctx = _ctx()
    runner._note_optional_failure(ctx, "cert_inventory", "Certificate inventory stage failed")
    stats = ctx.scan_meta["statistics"]
    assert stats["optional_stage_failures"] == [
        {"stage": "cert_inventory", "outcome": "failed", "detail": "Certificate inventory stage failed"}
    ]


def test_optional_failure_merges_into_persisted_scan_statistics():
    runner = PipelineRunner()
    ctx = _ctx()
    ctx.scan_persisted = True
    scan = SimpleNamespace(statistics={"total_findings": 3})
    runner._note_optional_failure(
        ctx, "inventory_drift", "Key-inventory drift comparison failed", session=FakeSession(scan))
    assert scan.statistics["total_findings"] == 3  # existing statistics preserved
    assert scan.statistics["optional_stage_failures"] == [
        {"stage": "inventory_drift", "outcome": "failed", "detail": "Key-inventory drift comparison failed"}
    ]


def test_note_is_idempotent_and_never_raises():
    runner = PipelineRunner()
    ctx = _ctx()
    runner._note_optional_failure(ctx, "email_alert", "x")
    runner._note_optional_failure(ctx, "email_alert", "x")
    assert len(ctx.scan_meta["statistics"]["optional_stage_failures"]) == 1

    class Boom:
        def execute(self, _query):
            raise RuntimeError("boom")

    ctx2 = _ctx()
    ctx2.scan_persisted = True
    # a failing session must not raise out of the disclosure helper
    runner._note_optional_failure(ctx2, "stakeholder_alert", "y", session=Boom())
    assert ctx2.scan_meta["statistics"]["optional_stage_failures"]


def test_note_without_scan_row_stays_in_meta_only():
    runner = PipelineRunner()
    ctx = _ctx()
    ctx.scan_persisted = False  # scan not yet loaded
    scan = SimpleNamespace(statistics={})
    runner._note_optional_failure(ctx, "ot_persist", "z", session=FakeSession(scan))
    assert scan.statistics == {}  # row untouched before it exists
    assert ctx.scan_meta["statistics"]["optional_stage_failures"]


def test_every_soft_skip_site_is_paired_with_a_disclosure_note():
    src = inspect.getsource(PipelineRunner)
    soft_skip_markers = [
        "cert_inventory_skipped",
        "container_scanner_unavailable",
        "container_scan_persist_skipped",
        "certificate_persist_skipped",
        "inventory_certificate_persist_skipped",
        "ot_persist_skipped",
        "inventory_drift_skipped",
        "baseline_proposal_skipped",
        "email_alert_failed",
        "stakeholder_alert_skipped",
    ]
    for marker in soft_skip_markers:
        assert marker in src, f"soft-skip site {marker} disappeared"
    # 13 soft-skip call sites + the helper definition itself
    assert src.count("_note_optional_failure(") == 14, (
        "every soft-skip site must disclose via _note_optional_failure"
    )


def test_alert_stage_still_works_without_session():
    runner = PipelineRunner()
    ctx = _ctx()
    ctx.scan_meta["quantum"] = {"overall_hndl_risk": "LOW", "mosca": {"verdict": "SAFE_MARGIN"}}
    runner._alert(ctx)  # session parameter is optional — must not raise
    assert not ctx.scan_meta.get("statistics", {}).get("optional_stage_failures")
