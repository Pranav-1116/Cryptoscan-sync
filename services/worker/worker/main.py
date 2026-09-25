"""Worker process entrypoint."""

from __future__ import annotations

import logging
import signal
import sys
from datetime import timedelta

from worker.config.settings import Settings
from worker.core.job_consumer import JobConsumer, ScanJob
from worker.core.job_executor import JobExecutor
from worker.core.pool import WorkerPool

logger = logging.getLogger("cryptoscan-worker")


class Worker:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.consumer: JobConsumer | None = None
        self.pool: WorkerPool | None = None
        self.running = True

    def signal_handler(self, signum, frame):
        logger.info("shutdown_signal", extra={"signal": signum})
        self.running = False
        if self.consumer:
            self.consumer.stop()

    def run(self):
        from db.connection.session import init_db

        init_db()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        from db.connection.session import SessionLocal

        from worker.core.job_reaper import fail_job, reap_stale_jobs

        def _dead_letter(payload: dict, reason: str) -> None:
            with SessionLocal() as session:
                fail_job(session, str(payload.get("job_id")), reason)

        def _maintenance() -> None:
            # DB-side sweep: RUNNING rows without progress → FAILED; QUEUED rows missing from Redis → republish
            with SessionLocal() as session:
                stats = reap_stale_jobs(
                    session,
                    queued_ids=self.consumer.queued_job_ids() if self.consumer and self.consumer.redis_client else None,
                    publish=self.consumer.enqueue if self.consumer else None,
                    running_timeout=timedelta(minutes=int(getattr(self.settings, "JOB_RUNNING_TIMEOUT_MINUTES", 90))),
                    queued_timeout=timedelta(minutes=int(getattr(self.settings, "JOB_QUEUED_TIMEOUT_MINUTES", 10))),
                )
            if any(stats.values()):
                logger.warning("job_reaper_sweep", extra=stats)

        self.consumer = JobConsumer(
            redis_url=self.settings.REDIS_URL,
            queue_name=self.settings.queue_key,
            # Production must not silently degrade to an in-process queue:
            # jobs published by the API would be lost across processes.
            allow_memory_fallback=not self.settings.is_production,
            lease_ttl_seconds=int(getattr(self.settings, "JOB_LEASE_TTL_SECONDS", 60)),
            max_redeliveries=int(getattr(self.settings, "JOB_MAX_REDELIVERIES", 3)),
            on_dead_letter=_dead_letter,
            on_maintenance=_maintenance,
        )
        executor = JobExecutor()
        concurrency = max(1, int(getattr(self.settings, "MAX_CONCURRENT_JOBS", 1)))
        self.pool = WorkerPool(handler=executor.execute, max_workers=concurrency)
        logger.info(
            "cryptoscan_worker_pool",
            extra={"max_concurrent_jobs": concurrency, "worker_id": self.consumer.worker_id},
        )
        # startup: adopt work left behind by crashed workers before taking new work
        recovered = self.consumer.recover_orphans()
        if any(recovered.values()):
            logger.warning("orphaned_jobs_recovered", extra=recovered)

        def handle(job: ScanJob):
            future = self.pool.submit(job)
            # at-least-once: the payload leaves Redis only when the scan finished (either way)
            future.add_done_callback(lambda _f, _job=job: self.consumer.ack(_job))

        try:
            self.consumer.consume(handler=handle)
        finally:
            # Graceful shutdown: wait for in-flight scans to finish.
            if self.pool:
                logger.info("worker_draining", extra={"active": self.pool.stats.active})
                self.pool.shutdown(wait=True)
                logger.info(
                    "worker_stopped",
                    extra={
                        "completed": self.pool.stats.completed,
                        "failed": self.pool.stats.failed,
                    },
                )


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings()
    try:
        settings.validate_runtime()
    except RuntimeError as exc:
        logger.error("worker_config_invalid", extra={"error": str(exc)})
        sys.exit(2)
    logger.info("cryptoscan_worker_start", extra={"env": settings.ENVIRONMENT})
    Worker(settings).run()


if __name__ == "__main__":
    main()
