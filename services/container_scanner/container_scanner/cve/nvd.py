"""NVD 2.0 client. Used only when NVD_API_KEY is configured."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_NVD_URL,
        timeout: float = 3.0,
    ):
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
        self.base_url = base_url
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup(self, package: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        name = (package.get("name") or "").strip()
        if not name:
            return []
        try:
            import httpx

            headers = {"apiKey": self.api_key}
            response = httpx.get(
                self.base_url,
                params={"keywordSearch": name, "resultsPerPage": 20},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json() or {}
        except Exception as exc:
            logger.info("nvd_query_failed", extra={"package": name, "error": str(exc)})
            return []

        findings: list[dict[str, Any]] = []
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            ident = cve.get("id")
            if not ident:
                continue
            descriptions = cve.get("descriptions") or []
            summary = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
            severity = "UNKNOWN"
            metrics = cve.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                rows = metrics.get(key) or []
                if rows:
                    severity = str((rows[0].get("cvssData") or {}).get("baseSeverity") or "UNKNOWN").upper()
                    break
            findings.append(
                {
                    "cve": ident,
                    "package": name,
                    "version": package.get("version"),
                    "severity": severity,
                    "summary": summary or ident,
                    "manifest": package.get("manifest"),
                    "source": "nvd",
                }
            )
        return findings
