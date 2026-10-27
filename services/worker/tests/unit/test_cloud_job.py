from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor


def test_executor_routes_cloud_jobs_without_clone(monkeypatch):
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


def test_cloud_job_fails_closed_on_failed_live_scan(monkeypatch):
    """A configured-but-failing live scan must fail the job, not report an
    empty COMPLETED inventory."""
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

    def failed_scan(session, job):
        return {
            "findings": [],
            "resources": 0,
            "issues": 0,
            "errors": [{"provider": "AWS", "service": "kms", "region": "us-east-1", "code": "AccessDenied", "error": "denied"}],
            "live_scan": {
                "enabled": True,
                "status": "FAILED",
                "resources_scanned": 0,
                "errors": [{"provider": "AWS", "service": "kms", "region": "us-east-1", "code": "AccessDenied", "error": "denied"}],
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
