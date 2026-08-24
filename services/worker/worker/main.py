"""
Worker Process Entry Point
Consumes scan jobs and executes pipeline
"""
import logging
import signal
import sys
from typing import Optional

from shared_logging.logger_factory import create_logger
from .config.settings import Settings
from .core.job_consumer import JobConsumer, ScanJob
from .core.job_executor import JobExecutor
from database.db.connection.session import SessionLocal

# Setup logging
logger = create_logger("cryptoscan-worker")


class Worker:
    """
    Main worker class
    Handles graceful shutdown
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.consumer: Optional[JobConsumer] = None
        self.running = True
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}. Shutting down gracefully...")
        self.running = False
        if self.consumer:
            self.consumer.stop()
    
    def run(self):
        """
        Main worker loop
        """
        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        logger.info("Starting CryptoScan Worker")
        logger.info(f"Redis URL: {self.settings.REDIS_URL}")
        logger.info(f"Queue: {self.settings.QUEUE_NAME}")
        
        self.consumer = JobConsumer(
            redis_url=self.settings.REDIS_URL,
            queue_name=self.settings.QUEUE_NAME,
            timeout=5
        )
        
        def job_handler(job: ScanJob):
            """Handler called for each job"""
            db = SessionLocal()
            try:
                executor = JobExecutor(
                    db_session=db,
                    workspace_base=self.settings.WORKSPACE_BASE
                )
                executor.execute(job)
            finally:
                db.close()
        
        # Start consuming
        try:
            self.consumer.consume(handler=job_handler)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Worker crashed: {e}", exc_info=True)
            sys.exit(1)
        
        logger.info("Worker stopped")


def main():
    """Entry point"""
    settings = Settings()
    worker = Worker(settings)
    worker.run()


if __name__ == "__main__":
    main()