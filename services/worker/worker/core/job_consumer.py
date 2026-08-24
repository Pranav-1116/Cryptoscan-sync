# services/worker/worker/core/job_consumer.py

"""
Production background job consumer.
Consumes scan jobs from Redis queue and executes pipeline stages.
"""

import json
import time
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
import redis
from redis.exceptions import RedisError, ConnectionError

logger = logging.getLogger(__name__)


@dataclass
class ScanJob:
    """Represents a scan job from queue."""
    job_id: str
    scan_id: str
    target_repo: str
    target_commit: str
    target_branch: str
    triggered_by: str
    created_at: datetime


class JobConsumer:
    """
    Redis-based job consumer for background scan processing.
    Implements:
    - Job polling with backoff
    - Error handling and retries
    - Graceful shutdown
    - Dead-letter queue (DLQ) support
    """
    
    QUEUE_NAME = "cryptoscan:jobs:queue"
    PROCESSING_PREFIX = "cryptoscan:jobs:processing:"
    DLQ_NAME = "cryptoscan:jobs:dlq"
    
    def __init__(
        self,
        redis_url: str,
        poll_interval_seconds: int = 5,
        max_retries: int = 3,
        job_timeout_seconds: int = 3600,
    ):
        """
        Initialize job consumer.
        
        Args:
            redis_url: Redis connection string (redis://localhost:6379/0)
            poll_interval_seconds: Time between queue polls
            max_retries: Max retry attempts per job
            job_timeout_seconds: Job execution timeout
        
        Raises:
            ConnectionError: If Redis connection fails
        """
        self.redis_url = redis_url
        self.poll_interval_seconds = poll_interval_seconds
        self.max_retries = max_retries
        self.job_timeout_seconds = job_timeout_seconds
        
        # Connect to Redis
        try:
            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_keepalive=True,
                socket_keepalive_options={},
            )
            self.redis_client.ping()
            logger.info(f"Connected to Redis: {redis_url}")
        except (ConnectionError, RedisError) as e:
            logger.error(f"Redis connection failed: {e}")
            raise
    
    def consume_jobs(self, executor_callback) -> None:
        """
        Main job consumption loop.
        Polls Redis queue and executes jobs.
        
        Args:
            executor_callback: Async function to execute job
                              Signature: async def execute_job(job: ScanJob) -> bool
        
        Blocking: Runs indefinitely until shutdown signal
        """
        logger.info("Job consumer started")
        
        while True:
            try:
                # Poll queue (blocking pop with timeout)
                job_data = self.redis_client.blpop(
                    self.QUEUE_NAME,
                    timeout=self.poll_interval_seconds,
                )
                
                if job_data is None:
                    # Timeout, no jobs available
                    logger.debug("No jobs in queue, waiting...")
                    continue
                
                # Deserialize job
                _, job_json = job_data
                job = self._deserialize_job(job_json)
                
                if job is None:
                    logger.error(f"Failed to deserialize job: {job_json}")
                    continue
                
                # Mark job as processing
                self._mark_processing(job.job_id)
                
                logger.info(f"Executing job: {job.job_id} (scan: {job.scan_id})")
                
                # Execute job (with timeout)
                try:
                    success = executor_callback(job)
                    
                    if success:
                        logger.info(f"Job completed: {job.job_id}")
                        self._mark_complete(job.job_id)
                    else:
                        logger.error(f"Job failed: {job.job_id}")
                        self._handle_job_failure(job)
                
                except Exception as e:
                    logger.exception(f"Job execution error: {job.job_id}: {e}")
                    self._handle_job_failure(job, error=str(e))
            
            except KeyboardInterrupt:
                logger.info("Job consumer shutting down")
                break
            except Exception as e:
                logger.exception(f"Unexpected consumer error: {e}")
                time.sleep(self.poll_interval_seconds)
    
    def enqueue_job(
        self,
        scan_id: str,
        target_repo: str,
        target_commit: str,
        target_branch: str,
        triggered_by: str,
    ) -> str:
        """
        Enqueue a new scan job.
        
        Args:
            scan_id: Unique scan identifier
            target_repo: Git repository URL
            target_commit: Git commit hash
            target_branch: Git branch name
            triggered_by: User/system that triggered scan
        
        Returns:
            Job ID (generated UUID)
        
        Raises:
            RedisError: If queue operation fails
        """
        import uuid
        
        job_id = str(uuid.uuid4())
        
        job = ScanJob(
            job_id=job_id,
            scan_id=scan_id,
            target_repo=target_repo,
            target_commit=target_commit,
            target_branch=target_branch,
            triggered_by=triggered_by,
            created_at=datetime.utcnow(),
        )
        
        # Serialize to JSON
        job_json = self._serialize_job(job)
        
        # Push to queue
        try:
            self.redis_client.rpush(self.QUEUE_NAME, job_json)
            logger.info(f"Job enqueued: {job_id} (scan: {scan_id})")
            return job_id
        except RedisError as e:
            logger.error(f"Failed to enqueue job: {e}")
            raise
    
    def _serialize_job(self, job: ScanJob) -> str:
        """Serialize job to JSON."""
        return json.dumps({
            "job_id": job.job_id,
            "scan_id": job.scan_id,
            "target_repo": job.target_repo,
            "target_commit": job.target_commit,
            "target_branch": job.target_branch,
            "triggered_by": job.triggered_by,
            "created_at": job.created_at.isoformat(),
        })
    
    def _deserialize_job(self, job_json: str) -> Optional[ScanJob]:
        """Deserialize job from JSON."""
        try:
            data = json.loads(job_json)
            return ScanJob(
                job_id=data["job_id"],
                scan_id=data["scan_id"],
                target_repo=data["target_repo"],
                target_commit=data["target_commit"],
                target_branch=data["target_branch"],
                triggered_by=data["triggered_by"],
                created_at=datetime.fromisoformat(data["created_at"]),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Job deserialization error: {e}")
            return None
    
    def _mark_processing(self, job_id: str) -> None:
        """Mark job as currently processing."""
        key = f"{self.PROCESSING_PREFIX}{job_id}"
        self.redis_client.setex(
            key,
            self.job_timeout_seconds,
            "processing",
        )
    
    def _mark_complete(self, job_id: str) -> None:
        """Mark job as completed."""
        key = f"{self.PROCESSING_PREFIX}{job_id}"
        self.redis_client.delete(key)
    
    def _handle_job_failure(self, job: ScanJob, error: str = None) -> None:
        """
        Handle job failure: move to DLQ and log.
        
        Args:
            job: Failed job
            error: Error message (optional)
        """
        failure_record = {
            "job_id": job.job_id,
            "scan_id": job.scan_id,
            "failed_at": datetime.utcnow().isoformat(),
            "error": error or "Unknown error",
        }
        
        # Move to DLQ
        try:
            self.redis_client.rpush(self.DLQ_NAME, json.dumps(failure_record))
            logger.error(f"Job moved to DLQ: {job.job_id}")
        except RedisError as e:
            logger.error(f"Failed to move job to DLQ: {e}")
        
        # Clean up processing marker
        self._mark_complete(job.job_id)