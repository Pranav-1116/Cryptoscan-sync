"""Worker process entrypoint."""

from __future__ import annotations

import logging
import signal
import sys

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
        self.consumer = JobConsumer(
            redis_url=self.settings.REDIS_URL,
            queue_name=self.settings.queue_key,
            # Production must not silently degrade to an in-process queue:
            # jobs published by the API would be lost across processes.
            allow_memory_fallback=not self.settings.is_production,
        )
        executor = JobExecutor()
        concurrency = max(1, int(getattr(self.settings, "MAX_CONCURRENT_JOBS", 1)))
        self.pool = WorkerPool(handler=executor.execute, max_workers=concurrency)
        logger.info(
            "cryptoscan_worker_pool",
            extra={"max_concurrent_jobs": concurrency},
        )

        def handle(job: ScanJob):
            self.pool.submit(job)

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
