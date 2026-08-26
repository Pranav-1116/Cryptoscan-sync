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
