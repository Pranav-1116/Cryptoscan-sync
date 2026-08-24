"""Worker process entrypoint."""

from __future__ import annotations

import logging
import signal
import sys

from worker.config.settings import Settings
from worker.core.job_consumer import JobConsumer, ScanJob
from worker.core.job_executor import JobExecutor

logger = logging.getLogger("cryptoscan-worker")


class Worker:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.consumer: JobConsumer | None = None
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
        )
        executor = JobExecutor()

        def handle(job: ScanJob):
            executor.execute(job)

        self.consumer.consume(handler=handle)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings()
    Worker(settings).run()


if __name__ == "__main__":
    main()
