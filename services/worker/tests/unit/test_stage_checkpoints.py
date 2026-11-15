"""Stage checkpoints — "finish or SAFELY CHECKPOINT active jobs" (§9).

The pipeline persisted progress per stage but nothing durable to resume
from: an interrupted job re-ran every stage — duplicate evidence, wasted
minutes. These tests pin the safe half of the contract: a retry resumes
at the stage boundary, a checkpoint that cannot fit its bound honestly
reruns in full, and a changed stage list invalidates old checkpoints
entirely. clone always re-runs: the workspace is ephemeral.
"""
from contextlib import ExitStack
from unittest.mock import patch

import pytest

from worker.pipeline.pipeline_runner import (
    MAX_CHECKPOINT_BYTES,
    PipelineContext,
    PipelineRunner,
    _checkpoint_payload,
    _resume_from_checkpoint,
    checkpoint_fingerprint,
)


def _spy(stack: ExitStack, name: str, calls: list):
    def _fn(self, *args, **kwargs):
        calls.append(name)

    stack.enter_context(patch.object(PipelineRunner, name, _fn))


def _seed_row(test_db, job_id="test-job-123"):
    from db.repositories.job_repository import JobRepository

    row = JobRepository(test_db).create_job(
        job_type="GITHUB_WEBHOOK",
        target_repo="https://github.com/test/repo", target_branch="main",
        triggered_by="test-user")
    row.id = job_id
    row.status = "RUNNING"
    test_db.flush()
    test_db.commit()
    return row


def _checkpoint_stubs(stack: ExitStack, calls: list):
    for name in ("_language_detect", "_scan", "_resolve_system", "_evidence",
                 "_load", "_normalize", "_policy", "_drift",
                 "_verify_resolved_conditions", "_quantum", "_gate", "_cbom",
                 "_stamp_coverage", "_alert", "_post_github"):
        _spy(stack, name, calls)
    stack.enter_context(
        patch("worker.workspace.repo_cloner.RepoCloner.clone",
              side_effect=lambda *a, **k: None))


class TestResumeRules:

    def test_no_progress_means_no_resume(self):
        assert _resume_from_checkpoint(None) == (frozenset(), None)
        assert _resume_from_checkpoint(object()) == (frozenset(), None)

    def test_a_checkpoint_without_a_snapshot_reruns_in_full(self):
        job = type("J", (), {})()
        job.progress = {"checkpoint": {
            "fingerprint": checkpoint_fingerprint(),
            "completed_stages": ["clone", "scan"],
            "ctx": None,
            "note": "stage outputs exceed the checkpoint bound — "
                    "a retry reruns the pipeline in full"}}
        assert _resume_from_checkpoint(job) == (frozenset(), None)

    def test_a_changed_stage_list_invalidates_the_checkpoint(self):
        job = type("J", (), {})()
        job.progress = {"checkpoint": {
            "fingerprint": "stale0000000",
            "completed_stages": ["clone", "scan"],
            "ctx": {"findings": []}}}
        assert _resume_from_checkpoint(job) == (frozenset(), None)

    def test_clone_is_never_skipped_and_unknown_stages_are_ignored(self):
        job = type("J", (), {})()
        job.progress = {"checkpoint": {
            "fingerprint": checkpoint_fingerprint(),
            "completed_stages": ["clone", "scan", "not-a-stage"],
            "ctx": {"findings": [{"id": "f1"}]}}}
        skip, snapshot = _resume_from_checkpoint(job)
        assert skip == frozenset({"scan"})
        assert snapshot == {"findings": [{"id": "f1"}]}


class TestCheckpointBound:

    def test_small_stage_outputs_are_snapshotted(self):
        ctx = PipelineContext(job_id="j1", target_repo="r", target_branch="main",
                              triggered_by="t", workspace_dir="/tmp/x",
                              findings=[{"id": "f1"}])
        payload = _checkpoint_payload(ctx)
        assert payload["fingerprint"] == checkpoint_fingerprint()
        assert payload["ctx"]["findings"] == [{"id": "f1"}]
        assert "note" not in payload

    def test_stage_outputs_over_the_bound_rerun_in_full_honestly(self):
        ctx = PipelineContext(job_id="j1", target_repo="r", target_branch="main",
                              triggered_by="t", workspace_dir="/tmp/x",
                              findings=[{"blob": "x" * (MAX_CHECKPOINT_BYTES + 1)}])
        payload = _checkpoint_payload(ctx)
        assert payload["ctx"] is None
        assert "reruns the pipeline in full" in payload["note"]


class TestPipelineResume:

    def test_a_retry_resumes_at_the_stage_boundary(self, temp_workspace, test_db,
                                                   mock_scan_job):
        _seed_row(test_db)
        first = []
        with ExitStack() as stack:
            _spy(stack, "_language_detect", first)
            _spy(stack, "_scan", first)
            _spy(stack, "_post_github", first)
            stack.enter_context(
                patch("worker.workspace.repo_cloner.RepoCloner.clone",
                      side_effect=lambda *a, **k: None))
            failing = stack.enter_context(
                patch.object(PipelineRunner, "_scan",
                             side_effect=RuntimeError("scanner crashed")))
            with pytest.raises(RuntimeError, match="Pipeline failed at stage"):
                PipelineRunner().run(job=mock_scan_job,
                                     workspace=temp_workspace, db=test_db)
            assert failing.called

        test_db.expire_all()
        from db.models.scan_job import ScanJob as ScanJobRow
        row = test_db.get(ScanJobRow, "test-job-123")
        checkpoint = (row.progress or {}).get("checkpoint") or {}
        assert checkpoint["completed_stages"] == ["clone", "language_detect"]
        assert checkpoint["fingerprint"] == checkpoint_fingerprint()
        assert checkpoint["ctx"] is not None

        # The retry sees the row's progress exactly as the consumer reloads it.
        mock_scan_job.progress = row.progress
        second: list = []
        with ExitStack() as stack:
            _checkpoint_stubs(stack, second)
            scan_id = PipelineRunner().run(job=mock_scan_job,
                                           workspace=temp_workspace, db=test_db)
        assert scan_id  # completed
        # Resumed at the boundary: clone re-ran (ephemeral workspace),
        # language_detect did NOT — no duplicated side effects.
        assert second.count("_language_detect") == 0
        assert second.count("_scan") == 1
        assert second.count("_load") == 1

    def test_a_stale_checkpoint_reruns_everything(self, temp_workspace, test_db,
                                                  mock_scan_job):
        _seed_row(test_db)
        mock_scan_job.progress = {"checkpoint": {
            "fingerprint": "stale0000000",
            "completed_stages": ["clone", "language_detect", "scan"],
            "ctx": {"findings": [{"id": "f1"}]}}}
        second: list = []
        with ExitStack() as stack:
            _checkpoint_stubs(stack, second)
            PipelineRunner().run(job=mock_scan_job,
                                 workspace=temp_workspace, db=test_db)
        assert second.count("_language_detect") == 1
        assert second.count("_scan") == 1
