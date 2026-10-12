"""Org fan-out job tests: routing, statuses, per-account ingest."""

from __future__ import annotations

import json

from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor


def _org_result(status="OK", accounts=2, resources=5):
    rows = [
        {"account_id": f"acc{i}", "ok": True, "resources": resources, "status": "OK"}
        for i in range(accounts)
    ]
    return {
        "provider": "aws",
        "org": True,
        "accounts_discovered": accounts,
        "truncated": False,
        "accounts": rows,
        "findings": [
            {"algorithm": "AES-256", "compliance_issue": None, "metadata": {"cloud_account": "acc0", "cloud_provider": "AWS"}},
            {"algorithm": "DES", "compliance_issue": "WEAK", "metadata": {"cloud_account": "acc1", "cloud_provider": "AWS"}},
        ],
        "resources": 2,
        "issues": 1,
        "errors": [],
        "live_scan": {
            "enabled": True,
            "status": status,
            "resources_scanned": resources * accounts,
            "accounts_scanned": accounts,
            "accounts_failed": 0,
            "errors": [],
            "truncations": [],
            "error_count": 0,
            "truncation_count": 0,
        },
    }


def test_executor_routes_org_targets_to_org_job(monkeypatch):
    called = {}

    def fake_org_job(job):
        called["job_id"] = job.job_id
        return True

    monkeypatch.setattr("worker.pipeline.org_job.run_org_job", fake_org_job)

    class Boom:
        def run(self, **kwargs):
            raise AssertionError("neither cloud_job nor pipeline may run for org targets")

    executor = JobExecutor()
    executor.runner = Boom()
    job = ScanJob(job_id="j-org", target_repo="cloud://aws-org/111122223333", job_type="CLOUD")
    assert executor.execute(job) is True
    assert called["job_id"] == "j-org"


def test_run_org_job_completes_with_rollup(monkeypatch):
    from worker.pipeline import org_job

    statuses = []

    class _Jobs:
        def __init__(self, session):
            pass

        def update_status(self, job_id, status, progress=None, error_message=None):
            statuses.append((status, progress, error_message))

    class _Session:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr("db.connection.session.SessionLocal", _Session)
    monkeypatch.setattr("db.repositories.job_repository.JobRepository", _Jobs)
    monkeypatch.setattr("cloud_scanner.org.job.scan_org", lambda *a, **k: _org_result())

    ingested = []

    def fake_ingest(session, findings, **kwargs):
        ingested.append((kwargs.get("account"), len(findings)))
        return {"systems": len(findings)}

    monkeypatch.setattr(org_job, "ingest_findings", fake_ingest)

    job = ScanJob(job_id="j-org-1", target_repo="cloud://aws-org/111122223333", job_type="CLOUD")
    assert org_job.run_org_job(job) is True

    status, progress, error_message = statuses[-1]
    assert status == "COMPLETED"
    cloud = progress["cloud"]
    assert cloud["org"] is True
    assert cloud["accounts_discovered"] == 2
    assert cloud["live_scan"]["status"] == "OK"
    assert cloud["systems"] == 2
    # findings ingested grouped per account
    accounts = {account for account, _count in ingested}
    assert accounts == {"acc0", "acc1"}


def test_run_org_job_fails_closed_when_every_account_fails(monkeypatch):
    from worker.pipeline import org_job

    statuses = []

    class _Jobs:
        def __init__(self, session):
            pass

        def update_status(self, job_id, status, progress=None, error_message=None):
            statuses.append((status, progress, error_message))

    class _Session:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr("db.connection.session.SessionLocal", _Session)
    monkeypatch.setattr("db.repositories.job_repository.JobRepository", _Jobs)

    failed = _org_result(status="FAILED", accounts=0, resources=0)
    failed["findings"] = []
    failed["accounts"] = []
    failed["live_scan"]["errors"] = [
        {"provider": "AWS", "service": "sts", "region": "global", "code": "AccessDenied", "error": "assume-role denied"}
    ]
    monkeypatch.setattr("cloud_scanner.org.job.scan_org", lambda *a, **k: failed)
    monkeypatch.setattr(org_job, "ingest_findings", lambda *a, **k: {"systems": 0})

    job = ScanJob(job_id="j-org-2", target_repo="cloud://aws-org/111122223333", job_type="CLOUD")
    assert org_job.run_org_job(job) is False
    status, progress, error_message = statuses[-1]
    assert status == "FAILED"
    assert "accounts failed" in error_message
    assert progress["cloud"]["live_scan"]["status"] == "FAILED"


def test_org_job_exception_stays_out_of_public_job_fields(monkeypatch, caplog):
    from worker.pipeline import org_job

    sentinel = "[SQL: SELECT sentinel_secret FROM users] [parameters: ('sentinel_key',)]"
    statuses = []

    class Session:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    class Jobs:
        def __init__(self, session):
            pass

        def update_status(self, job_id, status, progress=None, error_message=None):
            statuses.append((status, progress, error_message))

    monkeypatch.setattr("db.connection.session.SessionLocal", Session)
    monkeypatch.setattr("db.repositories.job_repository.JobRepository", Jobs)
    monkeypatch.setattr(org_job, "_scan_org", lambda *_: (_ for _ in ()).throw(RuntimeError(sentinel)))
    job = ScanJob(job_id="j-org-error", target_repo="cloud://aws-org/1111", job_type="CLOUD")
    assert org_job.run_org_job(job) is False
    assert statuses[-1][0] == "FAILED"
    assert "cloud_org_inventory" in statuses[-1][2]
    assert sentinel not in json.dumps(statuses)
    assert sentinel not in caplog.text
    assert all(sentinel not in str(record.__dict__) for record in caplog.records)
    assert any(record.__dict__.get("traceback_frames") for record in caplog.records)


def test_org_job_malformed_status_counts_and_errors_are_not_persisted(monkeypatch, caplog):
    from worker.pipeline import org_job

    sentinel = "[SQL: SELECT sentinel_secret FROM users] [parameters: ('sentinel_key',)]"
    statuses = []

    class Session:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    class Jobs:
        def __init__(self, session):
            pass

        def update_status(self, job_id, status, progress=None, error_message=None):
            statuses.append((status, progress, error_message))

    monkeypatch.setattr("db.connection.session.SessionLocal", Session)
    monkeypatch.setattr("db.repositories.job_repository.JobRepository", Jobs)
    result = _org_result(status="FAILED", accounts=0, resources=0)
    result["findings"] = []
    result["accounts"] = [{"account_id": "acc0", "ok": False, "error": sentinel,
                           "status": sentinel, "resources": sentinel}]
    result["provider"] = sentinel
    result["accounts_discovered"] = sentinel
    result["resources"] = sentinel
    result["truncated"] = sentinel
    result["live_scan"]["errors"] = {"error": sentinel}
    result["live_scan"]["truncations"] = {"reason": sentinel}
    result["live_scan"]["error_count"] = 1
    result["live_scan"]["accounts_failed"] = 1
    monkeypatch.setattr(org_job, "_scan_org", lambda *_: result)
    job = ScanJob(job_id="j-org-telemetry", target_repo="cloud://aws-org/1111", job_type="CLOUD")
    assert org_job.run_org_job(job) is False
    assert statuses[-1][0] == "FAILED"
    cloud = statuses[-1][1]["cloud"]
    assert cloud["live_scan"]["error_count"] == 1
    assert cloud["live_scan"]["errors"] == []
    assert cloud["live_scan"]["truncations"] == []
    assert cloud["provider"] == "unknown"
    assert cloud["accounts_discovered"] == cloud["resources"] == 0
    assert cloud["truncated"] is False
    assert cloud["accounts"][0]["status"] == "FAILED"
    assert cloud["accounts"][0]["resources"] == 0
    assert cloud["accounts"][0]["account_id"] == "acc0"
    assert sentinel not in json.dumps(statuses)
    assert sentinel not in caplog.text
    assert all(sentinel not in str(record.__dict__) for record in caplog.records)


def test_org_job_parses_gcp_folder_targets(monkeypatch):
    from worker.pipeline import org_job

    seen = {}

    def fake_scan_org(provider, **kwargs):
        seen["provider"] = provider
        seen.update(kwargs)
        return _org_result()

    monkeypatch.setattr("cloud_scanner.org.job.scan_org", fake_scan_org)
    monkeypatch.setattr("db.connection.session.SessionLocal", lambda: None)
    monkeypatch.setattr(
        "db.repositories.job_repository.JobRepository",
        lambda session: type(
            "J",
            (),
            {"update_status": staticmethod(lambda *a, **k: None)},
        )(),
    )
    monkeypatch.setattr(org_job, "ingest_findings", lambda *a, **k: {"systems": 0})

    class _Session:
        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr("db.connection.session.SessionLocal", _Session)
    job = ScanJob(job_id="j-gcp", target_repo="cloud://gcp-org/folders/987654321", job_type="CLOUD")
    org_job.run_org_job(job)
    assert seen["provider"] == "gcp-org"
    assert seen.get("folder") == "987654321"
