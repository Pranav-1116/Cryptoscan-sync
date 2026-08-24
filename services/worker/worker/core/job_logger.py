"""Structured job logger with an in-memory ring used for API job logs."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any


class JobLogger:
    def __init__(self, job_id: str, limit: int = 200):
        self.job_id = job_id
        self.limit = limit
        self.records: list[dict[str, Any]] = []
        self._log = logging.getLogger(f"worker.job.{job_id}")

    def info(self, event: str, **fields: Any) -> None:
        self._emit("INFO", event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._emit("WARNING", event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self._emit("ERROR", event, **fields)

    def as_list(self) -> list[dict[str, Any]]:
        return list(self.records)

    def _emit(self, level: str, event: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "event": event,
            **fields,
        }
        self.records.append(record)
        if len(self.records) > self.limit:
            self.records = self.records[-self.limit :]
        log_fn = {"INFO": self._log.info, "WARNING": self._log.warning, "ERROR": self._log.error}.get(
            level, self._log.info
        )
        log_fn(event, extra={"job_id": self.job_id, **fields})
