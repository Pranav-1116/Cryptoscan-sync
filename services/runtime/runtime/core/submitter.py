"""POST runtime findings to the platform API. Fail-open like cloud_scanner."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class RuntimeSubmitter:
    def __init__(self, api_url: str | None = None, token: str | None = None, timeout: float = 5.0, transport=None) -> None:
        self.api_url = (api_url if api_url is not None else os.environ.get("CRYPTOSCAN_API_URL") or "").rstrip("/")
        self.token = token if token is not None else os.environ.get("CRYPTOSCAN_API_TOKEN")
        self.timeout = timeout
        self.transport = transport

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        path = "/api/v1/scans/runtime-findings"
        if not self.api_url and self.transport is None:
            return {"ok": False, "skipped": True, "reason": "no_api_url"}
        url = f"{self.api_url}{path}" if self.api_url else path
        try:
            return {"ok": True, "skipped": False, "response": self._post(url, payload)}
        except Exception as exc:  # noqa: BLE001 — submission must never kill the agent
            logger.info("runtime_submit_failed", extra={"error": str(exc)})
            return {"ok": False, "skipped": False, "error": str(exc)}

    def _post(self, url: str, payload: dict[str, Any]) -> Any:
        if self.transport is not None:
            return self.transport(url, payload)
        import httpx

        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        response = httpx.post(url, json=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json()
        return {"status_code": response.status_code}
