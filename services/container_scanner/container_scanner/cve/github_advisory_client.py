"""GitHub Global Advisory client. Fail-open; token optional."""

from __future__ import annotations

import logging
import os
from typing import Any, Callable

logger = logging.getLogger(__name__)

DEFAULT_GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

ECOSYSTEM = {
    "pip": "pip",
    "pypi": "pip",
    "python": "pip",
    "npm": "npm",
    "node": "npm",
    "maven": "maven",
    "java": "maven",
    "gradle": "maven",
    "nuget": "nuget",
    "csharp": "nuget",
    "dotnet": "nuget",
    "go": "go",
    "golang": "go",
    "cargo": "rust",
    "rust": "rust",
    "gem": "rubygems",
    "rubygems": "rubygems",
    "composer": "composer",
    "php": "composer",
}


class GitHubAdvisoryClient:
    def __init__(
        self,
        token: str | None = None,
        base_url: str = DEFAULT_GITHUB_ADVISORY_URL,
        timeout: float = 8.0,
        transport: Callable[..., Any] | None = None,
    ) -> None:
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", "")
        self.base_url = base_url
        self.timeout = timeout
        self.transport = transport

    @property
    def enabled(self) -> bool:
        return True

    def lookup(self, package: dict[str, Any]) -> list[dict[str, Any]]:
        name = (package.get("name") or "").strip()
        if not name:
            return []
        version = (package.get("version") or "").strip()
        ecosystem = ECOSYSTEM.get(str(package.get("manager") or "").lower())
        params: dict[str, Any] = {"per_page": 20}
        if ecosystem:
            params["ecosystem"] = ecosystem
        params["affects"] = f"{name}@{version}" if version else name
        try:
            payload = self._get(params)
        except Exception as exc:
            logger.info("github_advisory_query_failed", extra={"package": name, "error": str(exc)})
            return []
        return self._parse(payload, package)

    def _get(self, params: dict[str, Any]) -> Any:
        if self.transport is not None:
            return self.transport(self.base_url, params)
        import httpx

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = httpx.get(self.base_url, params=params, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def _parse(self, payload: Any, package: dict[str, Any]) -> list[dict[str, Any]]:
        rows = payload if isinstance(payload, list) else (payload or {}).get("advisories") or []
        name = (package.get("name") or "").strip()
        findings: list[dict[str, Any]] = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            ident = item.get("cve_id") or item.get("ghsa_id")
            if not ident:
                continue
            findings.append(
                {
                    "cve": ident,
                    "package": name,
                    "version": package.get("version"),
                    "severity": str(item.get("severity") or "UNKNOWN").upper(),
                    "summary": item.get("summary") or ident,
                    "manifest": package.get("manifest"),
                    "source": "github",
                    "ghsa_id": item.get("ghsa_id"),
                }
            )
        return findings
