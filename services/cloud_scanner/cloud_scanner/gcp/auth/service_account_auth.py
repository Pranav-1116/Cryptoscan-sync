"""GCP service-account JSON loader. Fail-open when the file is missing."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import json
import os
from pathlib import Path
from typing import Any


def service_account_info(*, path: str | None = None) -> dict[str, Any] | None:
    raw = path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not raw:
        return None
    file_path = Path(raw)
    if not file_path.is_file():
        return None
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
    return data if isinstance(data, dict) else None
