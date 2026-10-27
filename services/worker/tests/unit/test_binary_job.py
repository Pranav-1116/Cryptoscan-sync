"""Queued binary scans: the job path must produce the endpoint's artifact.

These tests run the real scanner against a real (tiny) ELF and the real artifact
store in a temporary directory — no mocked scan — so they fail if the job path
and the synchronous endpoint ever drift apart.
"""

from __future__ import annotations

import json
import struct

from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor
from worker.pipeline import binary_job


def _elf64() -> bytes:
    """The smallest thing the ELF parser will accept as an ELF."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 64, 0, 0, 64, 56, 0, 0, 0, 0)
    return ident + header


class _Jobs:
    """Records the status/progress writes a job makes (the JobRepository surface)."""

    writes: list[tuple] = []

    def __init__(self, session):
        pass

    def update_status(self, job_id, status, progress=None, error_message=None):
        _Jobs.writes.append((job_id, status, progress, error_message))


class _Session:
    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def _wire(monkeypatch, tmp_path):
    _Jobs.writes = []
    monkeypatch.setattr("db.connection.session.SessionLocal", _Session)
    monkeypatch.setattr("db.repositories.job_repository.JobRepository", _Jobs)
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    return _Jobs.writes


def test_executor_routes_binary_targets_to_the_binary_job(monkeypatch):
    """A binary:// target must never reach the git pipeline."""
    called = {}

    def fake_binary(job):
        called["binary"] = job.job_id
        return True

    class Boom:
        def run(self, **kwargs):
            raise AssertionError("the git pipeline must not run for a binary target")

    # Permit at the gate explicitly. This test is about ROUTING, and the gate
    # fails closed whenever it cannot read the control plane — which is the
    # case in a process where nothing has bound SessionLocal. Leaving it
    # implicit made the test depend on some earlier module in the same pytest
    # process having called init_db() (services/api's test_auth_lifecycle is
    # the only one that does): run the worker suite on its own and the gate
    # refused, the refusal stamp hit an unbound session, and the test failed
    # with UnboundExecutionError instead of asserting anything about routing.
    # The gate's own fail-closed behaviour is pinned in test_execution_gate.py
    # and the refusal path in the tests below.
    monkeypatch.setattr("worker.core.job_executor.gate_job", lambda job, repository_target: (True, None))
    monkeypatch.setattr("worker.pipeline.binary_job.run_binary_job", fake_binary)
    # Routing/scope seam only; real persisted authority has its own contracts.
    monkeypatch.setattr("worker.core.job_executor.reconcile", lambda job: job)
    monkeypatch.setattr("worker.core.job_executor.claim", lambda job: None)
    executor = JobExecutor()
    executor.runner = Boom()
    job = ScanJob(job_id="j-bin", target_repo="binary:///tmp/somewhere", job_type="BINARY")
    assert executor.execute(job) is True
    assert called["binary"] == "j-bin"


def test_binary_job_scans_stores_and_reports_the_artifact(monkeypatch, tmp_path):
    """End to end: a real scan, a stored artifact, and progress that names it."""
    writes = _wire(monkeypatch, tmp_path)
    target = tmp_path / "firmware"
    target.mkdir()
    (target / "libcustomer.so").write_bytes(_elf64())
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "vendor.yar").write_text(
        'rule vendor_build : vendor { meta: severity = "HIGH" strings: $a = "acme-vendor-build" condition: $a }',
        "utf-8",
    )

    job = ScanJob(
        job_id="j-binary-1",
        target_repo=f"binary://{target}",
        triggered_by="operator",
        job_type="BINARY",
        progress={
            "scan_options": {
                "format": "cyclonedx",
                "recursive": True,
                "yara_rules": [str(rules)],
                "artifact_id": "art-1",
            }
        },
    )
    assert binary_job.run_binary_job(job) is True

    status, progress, error = writes[-1][1], writes[-1][2], writes[-1][3]
    assert status == "COMPLETED" and error is None
    assert progress["binary"]["artifact_id"] == "art-1"
    assert progress["binary"]["binaries_scanned"] == 1
    assert progress["binary"]["target"].endswith("/firmware")
    assert progress["binary"]["report_url"].endswith("/sbom/art-1/report?fmt=markdown")
    # the SBOM and the manifest are on disk, under the artifact id the caller
    # chose, inside the tenant bucket (an install with no tenant context uses
    # the platform bucket)
    stored = sorted(p.name for p in (tmp_path / "sboms").iterdir())
    assert any(n.endswith("art-1.cdx.json.enc") for n in stored)
    assert any(n.endswith("art-1.cdx.json.manifest.json") for n in stored)
    assert all(n.startswith("tenants__") for n in stored), "artifacts must be tenant-scoped"


def test_every_progress_write_keeps_the_scan_options(monkeypatch, tmp_path):
    """A retry reads the job row; the options must still be on it."""
    writes = _wire(monkeypatch, tmp_path)
    target = tmp_path / "images"
    target.mkdir()
    (target / "boot.bin").write_bytes(_elf64())
    options = {"format": "spdx", "yara_rules": [], "artifact_id": "art-2"}
    job = ScanJob(
        job_id="j-binary-2", target_repo=f"binary://{target}", job_type="BINARY", progress={"scan_options": options}
    )
    assert binary_job.run_binary_job(job) is True
    assert writes, "the job must report progress"
    for _job_id, _status, progress, _error in writes:
        assert progress["scan_options"] == options


def test_the_queued_artifact_is_signed_and_verifiable(monkeypatch, tmp_path):
    """The worker signs with the platform key, not a key of its own."""
    import json

    from devsecops import sbom_scan as sb

    _wire(monkeypatch, tmp_path)
    monkeypatch.setattr("worker.pipeline.binary_job._signing_secret", lambda session: ("unit-test-secret", "tests"))
    target = tmp_path / "signed"
    target.mkdir()
    (target / "lib.so").write_bytes(_elf64())
    job = ScanJob(
        job_id="22222222-3333-4444-5555-666666666666",
        target_repo=f"binary://{target}",
        job_type="BINARY",
        progress={"scan_options": {}},
    )
    assert binary_job.run_binary_job(job) is True
    manifest_path = next(
        p
        for p in (tmp_path / "sboms").iterdir()
        if p.name.endswith("22222222-3333-4444-5555-666666666666.cdx.json.manifest.json")
    )
    manifest = json.loads(manifest_path.read_text("utf-8"))
    assert manifest["signature_alg"] == "HMAC-SHA256"
    assert manifest["signature_key"] == "tests"
    assert sb.verify_manifest(manifest, "unit-test-secret") is True
    assert sb.verify_manifest(manifest, "someone-elses-key") is False


def test_the_artifact_is_keyed_by_the_job_so_a_retry_overwrites_it(monkeypatch, tmp_path):
    """Idempotence: re-running a job rewrites its artifact, it does not add one."""
    _wire(monkeypatch, tmp_path)
    target = tmp_path / "release"
    target.mkdir()
    (target / "libpay.so").write_bytes(_elf64())
    job = ScanJob(
        job_id="11111111-2222-3333-4444-555555555555",
        target_repo=f"binary://{target}",
        job_type="BINARY",
        progress={"scan_options": {}},
    )
    assert binary_job.run_binary_job(job) is True
    first = sorted(p.name for p in (tmp_path / "sboms").iterdir())
    assert binary_job.run_binary_job(job) is True
    second = sorted(p.name for p in (tmp_path / "sboms").iterdir())
    assert first == second
    assert all("11111111-2222-3333-4444-555555555555." in name for name in second)


def test_binary_job_fails_closed_when_the_target_is_gone(monkeypatch, tmp_path, caplog):
    """A missing target is FAILED; the detailed path stays in worker logs."""
    writes = _wire(monkeypatch, tmp_path)
    job = ScanJob(
        job_id="j-binary-3",
        target_repo=f"binary://{tmp_path}/not-there",
        job_type="BINARY",
        progress={"scan_options": {"artifact_id": "art-3"}},
    )
    assert binary_job.run_binary_job(job) is False
    status, progress, error = writes[-1][1], writes[-1][2], writes[-1][3]
    assert status == "FAILED"
    assert error == "Binary scan failed at stage binary_target"
    assert "binary_job_failed" in caplog.text
    assert progress["status"] == "FAILED" and progress["current_stage"] == "binary_target"
    assert not (tmp_path / "sboms").exists() or not list((tmp_path / "sboms").iterdir())


def test_binary_job_refuses_a_target_outside_the_source_roots(monkeypatch, tmp_path):
    """The worker re-validates the path: a job row is data, not a permission."""
    writes = _wire(monkeypatch, tmp_path)
    job = ScanJob(
        job_id="j-binary-4", target_repo="binary:///etc/ssl", job_type="BINARY", progress={"scan_options": {}}
    )
    assert binary_job.run_binary_job(job) is False
    error = writes[-1][3] or ""
    assert error == "Binary scan failed at stage binary_target"


def test_binary_job_exception_stays_out_of_public_fields(monkeypatch, tmp_path, caplog):
    writes = _wire(monkeypatch, tmp_path)
    sentinel = "[SQL: SELECT sentinel_secret FROM users] [parameters: ('sentinel_key',)]"

    def fail_at_store(session, job, options, report):
        report("binary_store", note="storing artifact")
        raise RuntimeError(sentinel)

    monkeypatch.setattr(binary_job, "_run", fail_at_store)
    job = ScanJob(
        job_id="j-binary-error",
        target_repo=f"binary://{tmp_path}",
        job_type="BINARY",
        progress={"scan_options": {"artifact_id": "art-error"}},
    )
    assert binary_job.run_binary_job(job) is False
    assert writes[-1][1] == "FAILED"
    assert writes[-1][2]["current_stage"] == "binary_store"
    assert writes[-1][2]["stages"][3]["state"] == "FAILED"
    assert "binary_store" in writes[-1][3]
    assert sentinel not in json.dumps(writes)
    assert sentinel not in caplog.text
    assert all(sentinel not in str(record.__dict__) for record in caplog.records)
    assert any(record.__dict__.get("traceback_frames") for record in caplog.records)


def test_cbom_ingest_exception_is_not_persisted_in_completed_artifact(monkeypatch, tmp_path, caplog):
    writes = _wire(monkeypatch, tmp_path)
    sentinel = "[SQL: SELECT sentinel_secret FROM users] [parameters: ('sentinel_key',)]"
    target = tmp_path / "bundle"
    target.mkdir()
    (target / "tool.so").write_bytes(_elf64())
    monkeypatch.setattr(
        "api.routers.cbom.ingest_document", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError(sentinel))
    )
    job = ScanJob(
        job_id="j-binary-ingest",
        target_repo=f"binary://{target}",
        job_type="BINARY",
        progress={"scan_options": {"ingest_cbom": True, "artifact_id": "art-ingest"}},
    )
    assert binary_job.run_binary_job(job) is True
    assert writes[-1][1] == "COMPLETED"
    assert writes[-1][2]["binary"]["cbom_ingested"] is False
    assert sentinel not in json.dumps(writes)
    assert sentinel not in caplog.text
    assert all(sentinel not in str(record.__dict__) for record in caplog.records)
    assert any(record.__dict__.get("traceback_frames") for record in caplog.records)


def test_a_cbom_ingest_failure_does_not_lose_the_artifact(monkeypatch, tmp_path):
    """The artifact is stored before ingest; a bad document is reported, not fatal."""
    writes = _wire(monkeypatch, tmp_path)
    target = tmp_path / "bundle"
    target.mkdir()
    (target / "tool.so").write_bytes(_elf64())
    monkeypatch.setattr(
        "worker.pipeline.binary_job._ingest_cbom", lambda *a, **k: {"ingested": False, "error": "inventory unavailable"}
    )
    job = ScanJob(
        job_id="j-binary-5",
        target_repo=f"binary://{target}",
        job_type="BINARY",
        progress={"scan_options": {"ingest_cbom": True, "artifact_id": "art-5"}},
    )
    assert binary_job.run_binary_job(job) is True
    status, progress = writes[-1][1], writes[-1][2]
    assert status == "COMPLETED"
    assert progress["binary"]["cbom_ingested"] is False
    assert "inventory unavailable" in progress["binary"]["note"]


def test_a_walk_with_nothing_parseable_says_so(monkeypatch, tmp_path):
    """Zero findings must not read as zero files looked at."""
    writes = _wire(monkeypatch, tmp_path)
    target = tmp_path / "notes"
    target.mkdir()
    (target / "readme.txt").write_text("nothing binary here", "utf-8")
    job = ScanJob(
        job_id="j-binary-6",
        target_repo=f"binary://{target}",
        job_type="BINARY",
        progress={"scan_options": {"artifact_id": "art-6"}},
    )
    assert binary_job.run_binary_job(job) is True
    note = writes[-1][2]["binary"]["note"]
    assert note and "walked" in note and "none was a format" in note


def test_the_target_scheme_helpers_agree(tmp_path):
    """``binary://`` parsing is used by the executor, the API and this module."""
    parsed = f"binary://{tmp_path}"
    assert binary_job.is_binary_target(parsed)
    assert not binary_job.is_binary_target("https://git/bank/pay.git")
    assert binary_job.binary_target_path(parsed) == str(tmp_path)
    assert binary_job.binary_target_path("https://git/bank/pay.git") == "https://git/bank/pay.git"
