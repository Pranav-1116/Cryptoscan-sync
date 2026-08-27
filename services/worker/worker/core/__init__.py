"""Worker core: job consumption from Redis, lifecycle management.

Modules:
- job_consumer: Job queue: Redis when available, in-process fallback
- job_executor: Execute one queued job through the pipeline
- job_logger: Structured job logger with an in-memory ring used for API job logs
- pool: Bounded concurrency for scan job execution
"""
