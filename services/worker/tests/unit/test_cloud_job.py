import json

from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor


def test_executor_routes_cloud_jobs_without_clone(monkeypatch):
    # These two tests pin ROUTING, not the gate: stub the policy read the
    # execution-gate tests own (test_execution_gate.py does the same).
    # Without this the tests only passed when some earlier file in the same
    # process had bound SessionLocal — alone, the unbound session made the
    # gate fail closed and the refusal path crash on the same unbound
    # session (order-dependent, surfaced by an xdist reshuffle in round 67).
    import worker.core.execution_gate as _gate

    monkeypatch.setattr(_gate, "_matching_policy", lambda: {"mode": "standard"})
    called = {}

    def fake_cloud(job):
        called["cloud"] = job.job_id
        return True

    class Boom:
        def run(self, **kwargs):
            raise AssertionError("git pipeline must not run for CLOUD jobs")

    monkeypatch.setattr("worker.pipeline.cloud_job.run_cloud_job", fake_cloud)
    executor = JobExecutor()
    executor.runner = Boom()
    job = ScanJob(job_id="j-cloud", target_repo="cloud://aws/1111", job_type="CLOUD")
    assert executor.execute(job) is True
    assert called["cloud"] == "j-cloud"


def test_executor_keeps_git_pipeline(monkeypatch):
    import worker.core.execution_gate as _gate

    monkeypatch.setattr(_gate, "_matching_policy", lambda: {"mode": "standard"})
    called = {}

    class Runner:
        def run(self, **kwargs):
            called.update(kwargs)
            return "scan-1"

    executor = JobExecutor()
    executor.runner = Runner()
    job = ScanJob(job_id="j-git", target_repo="https://git/bank/pay.git", job_type="SYSTEM")
    assert executor.execute(job) is True
    assert called["target_repo"].endswith("pay.git")


def test_cloud_job_fails_closed_on_failed_live_scan(monkeypatch, caplog):
    """A configured-but-failing live scan must fail the job, not report an
    empty COMPLETED inventory."""
    from worker.pipeline import cloud_job

    statuses = []
    sentinel = "[SQL: SELECT sentinel_secret FROM users] [parameters: ('sentinel_key',)]"

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

    def failed_scan(session, job):
        return {
            "findings": [],
            "resources": 0,
            "issues": 0,
            "errors": [{"provider": "AWS", "service": "kms", "region": "us-east-1", "code": "AccessDenied", "error": sentinel}],
            "live_scan": {
                "enabled": True,
                "status": "FAILED",
                "resources_scanned": 0,
                "errors": [{"provider": "AWS", "service": "kms", "region": "us-east-1", "code": "AccessDenied", "error": sentinel}],
                "truncations": [],
                "error_count": 1,
                "truncation_count": 0,
            },
        }

    monkeypatch.setattr(cloud_job, "_scan", failed_scan)
    job = ScanJob(job_id="j-fail", target_repo="cloud://aws/2222", job_type="CLOUD")
    assert cloud_job.run_cloud_job(job) is False
    status, progress, error_message = statuses[-1]
    assert status == "FAILED"
    assert progress["cloud"]["live_scan"]["status"] == "FAILED"
    assert "0 resources" in error_message
    assert sentinel not in json.dumps(statuses)
    assert sentinel not in caplog.text
    assert all(sentinel not in str(record.__dict__) for record in caplog.records)


def test_cloud_job_exception_stays_out_of_public_job_fields(monkeypatch, caplog):
    from worker.pipeline import cloud_job

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
    monkeypatch.setattr(cloud_job, "_scan", lambda *_: (_ for _ in ()).throw(RuntimeError(sentinel)))
    job = ScanJob(job_id="j-cloud-error", target_repo="cloud://aws/2222", job_type="CLOUD")
    assert cloud_job.run_cloud_job(job) is False
    assert statuses[-1][0] == "FAILED"
    assert "cloud_inventory" in statuses[-1][2]
    assert sentinel not in json.dumps(statuses)
    assert sentinel not in caplog.text
    assert all(sentinel not in str(record.__dict__) for record in caplog.records)
    assert any(record.__dict__.get("traceback_frames") for record in caplog.records)


def test_cloud_telemetry_errors_are_not_persisted_even_on_partial_success(monkeypatch, caplog):
    from worker.pipeline import cloud_job

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
    telemetry = {"enabled": True, "status": "PARTIAL", "resources_scanned": 1,
                 "errors": [{"provider": "AWS", "error": sentinel}], "error_count": 1}
    monkeypatch.setattr(cloud_job, "_scan", lambda *_: {
        "findings": [], "resources": 1, "errors": telemetry["errors"], "live_scan": telemetry,
    })
    monkeypatch.setattr(cloud_job, "ingest_findings", lambda *_a, **_k: {"systems": 0})
    job = ScanJob(job_id="j-cloud-partial", target_repo="cloud://aws/2222", job_type="CLOUD")
    assert cloud_job.run_cloud_job(job) is True
    assert statuses[-1][0] == "COMPLETED"
    assert statuses[-1][1]["cloud"]["live_scan"]["error_count"] == 1
    assert sentinel not in json.dumps(statuses)
    assert sentinel not in caplog.text
    assert all(sentinel not in str(record.__dict__) for record in caplog.records)


def test_cloud_job_completes_with_live_scan_telemetry(monkeypatch):
    from worker.pipeline import cloud_job

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

    def ok_scan(session, job):
        return {
            "findings": [{"algorithm": "AES", "metadata": {"cloud_provider": "AWS"}}],
            "resources": 1,
            "issues": 0,
            "errors": [],
            "live_scan": {"enabled": True, "status": "OK", "resources_scanned": 1, "errors": [], "truncations": [], "error_count": 0, "truncation_count": 0},
        }

    monkeypatch.setattr(cloud_job, "_scan", ok_scan)
    monkeypatch.setattr(
        "worker.pipeline.cloud_job.ingest_findings",
        lambda *a, **k: {"systems": 1, "created": 1, "updated": 0, "algorithms": {"AES": 1}, "system_ids": ["s1"]},
    )
    job = ScanJob(job_id="j-ok", target_repo="cloud://aws/3333", job_type="CLOUD")
    assert cloud_job.run_cloud_job(job) is True
    status, progress, _ = statuses[-1]
    assert status == "COMPLETED"
    assert progress["cloud"]["live_scan"]["status"] == "OK"
