"""Allowlisted job failure text and cloud telemetry for API-visible job rows.

Scanner exceptions may contain SQL, request parameters, credentials or source text.
Never copy exception text or scanner error dictionaries into job progress.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any


_SAFE_EXCEPTION_TYPES = frozenset({
    "RuntimeError", "ValueError", "TypeError", "PermissionError", "FileNotFoundError",
    "OperationalError", "IntegrityError", "DataError", "TimeoutError", "ConnectionError",
})


def log_job_failure(logger: Any, event: str, exc: Exception, *, job_id: str, stage: str) -> None:
    """Log every traceback frame without exception text, parameters or source lines.

    A conventional logger.exception/format_exc would leak SQL parameters and
    credentials through exception messages. Frame locations retain a safe call
    path for diagnosis, but not the exception's raw traceback rendering.
    """
    frames = []
    tb = exc.__traceback__
    while tb is not None:
        filename = Path(tb.tb_frame.f_code.co_filename).name
        function = tb.tb_frame.f_code.co_name
        filename = filename if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", filename) else "unknown.py"
        function = function if re.fullmatch(r"[A-Za-z0-9_<>]{1,64}", function) else "unknown"
        frames.append(f"{filename}:{tb.tb_lineno}:{function}")
        tb = tb.tb_next
    name = type(exc).__name__
    logger.error(event, extra={"job_id": job_id, "stage": stage,
                               "error_type": name if name in _SAFE_EXCEPTION_TYPES else "UnexpectedError",
                               "traceback_frames": frames})


def public_failure(category: str, stage: str) -> str:
    """Call only with worker-owned, fixed category and stage names."""
    return f"{category} failed at stage {stage}"


def public_count(value: Any) -> int:
    return max(0, value) if type(value) is int else 0


def public_status(value: Any) -> str:
    return value if isinstance(value, str) and value in {"OK", "PARTIAL", "FAILED", "SKIPPED"} else "FAILED"


def _entries(value: Any) -> list[Any]:
    return value[:50] if isinstance(value, list) else []


def public_cloud_telemetry(live_scan: dict[str, Any]) -> dict[str, Any]:
    """Retain bounded counts/verdicts; replace all scanner-provided error detail."""
    safe: dict[str, Any] = {
        "enabled": live_scan.get("enabled") is True,
        "status": public_status(live_scan.get("status")),
        "resources_scanned": public_count(live_scan.get("resources_scanned")),
        "errors": [{"error": "Cloud provider call failed"} for _ in _entries(live_scan.get("errors"))],
        "error_count": public_count(live_scan.get("error_count")),
        "truncations": [{"reason": "Cloud inventory truncated"} for _ in _entries(live_scan.get("truncations"))],
        "truncation_count": public_count(live_scan.get("truncation_count")),
    }
    for key in ("accounts_scanned", "accounts_failed"):
        if key in live_scan:
            safe[key] = public_count(live_scan[key])
    return safe
