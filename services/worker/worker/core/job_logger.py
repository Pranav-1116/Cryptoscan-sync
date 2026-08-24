"""Structured job logger."""

from __future__ import annotations

import logging
from typing import Any


class JobLogger:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self._log = logging.getLogger(f"worker.job.{job_id}")

    def info(self, event: str, **fields: Any) -> None:
        self._log.info(event, extra={"job_id": self.job_id, **fields})

    def warning(self, event: str, **fields: Any) -> None:
        self._log.warning(event, extra={"job_id": self.job_id, **fields})

    def error(self, event: str, **fields: Any) -> None:
        self._log.error(event, extra={"job_id": self.job_id, **fields})
