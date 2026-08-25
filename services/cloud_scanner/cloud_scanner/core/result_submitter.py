"""Optionally POST cloud scan results to the platform API. Fail-open."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class ResultSubmitter:
    def __init__(self, api_url: str | None = None, timeout: float = 5.0, transport=None) -> None:
        self.api_url = (api_url if api_url is not None else os.environ.get("CRYPTOSCAN_API_URL") or "").rstrip("/")
        self.timeout = timeout
        self.transport = transport

    def submit(self, result: dict[str, Any], *, path: str = "/api/cloud/results") -> dict[str, Any]:
        if not self.api_url and self.transport is None:
            return {"ok": False, "skipped": True, "reason": "no_api_url"}
        url = f"{self.api_url}{path}" if self.api_url else path
        try:
            payload = self._post(url, result)
        except Exception as exc:
            logger.info("cloud_result_submit_failed", extra={"error": str(exc)})
            return {"ok": False, "skipped": False, "error": str(exc)}
        return {"ok": True, "skipped": False, "response": payload}

    def _post(self, url: str, result: dict[str, Any]) -> Any:
        if self.transport is not None:
            return self.transport(url, result)
        import httpx

        response = httpx.post(url, json=result, timeout=self.timeout)
        response.raise_for_status()
        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json()
        return {"status_code": response.status_code}


def submit_results(result: dict[str, Any], *, api_url: str | None = None) -> dict[str, Any]:
    return ResultSubmitter(api_url=api_url).submit(result)
