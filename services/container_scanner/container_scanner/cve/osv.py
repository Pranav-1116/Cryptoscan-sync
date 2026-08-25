"""OSV.dev client — no API key required."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_OSV_URL = "https://api.osv.dev"

ECOSYSTEMS = {
    "pip": "PyPI",
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "nuget": "NuGet",
    "go": "Go",
    "golang": "Go",
    "apk": "Alpine",
    "alpine": "Alpine",
    "deb": "Debian",
    "dpkg": "Debian",
    "debian": "Debian",
}


class OsvClient:
    def __init__(self, base_url: str = DEFAULT_OSV_URL, timeout: float = 2.5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def query_batch(self, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        queries = []
        index_map: list[int] = []
        for index, package in enumerate(packages):
            payload = self._query_body(package)
            if payload is None:
                continue
            queries.append(payload)
            index_map.append(index)
        if not queries:
            return []
        try:
            import httpx

            response = httpx.post(
                f"{self.base_url}/v1/querybatch",
                json={"queries": queries},
                timeout=self.timeout,
            )
            response.raise_for_status()
            results = (response.json() or {}).get("results") or []
        except Exception as exc:
            logger.info("osv_query_failed", extra={"error": str(exc)})
            return []

        findings: list[dict[str, Any]] = []
        for query_index, result in enumerate(results):
            if query_index >= len(index_map):
                break
            package = packages[index_map[query_index]]
            for vuln in result.get("vulns") or []:
                findings.append(self._normalize(package, vuln))
        return findings

    def _query_body(self, package: dict[str, Any]) -> dict[str, Any] | None:
        name = (package.get("name") or "").strip()
        if not name:
            return None
        ecosystem = ECOSYSTEMS.get(str(package.get("manager") or "").lower())
        if ecosystem is None:
            return None
        body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if package.get("version"):
            body["version"] = str(package["version"])
        if package.get("group") and ecosystem == "Maven":
            body["package"]["name"] = f"{package['group']}:{name}"
        return body

    def _normalize(self, package: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
        aliases = vuln.get("aliases") or []
        cve = next((item for item in aliases if str(item).startswith("CVE-")), None)
        ident = str(cve or vuln.get("id") or "UNKNOWN")
        severity = "UNKNOWN"
        for rating in vuln.get("severity") or []:
            score = str(rating.get("score") or "")
            if score.upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity = score.upper()
                break
            try:
                numeric = float(score.split("/")[0])
            except (TypeError, ValueError):
                numeric = None
            if numeric is not None:
                if numeric >= 9:
                    severity = "CRITICAL"
                elif numeric >= 7:
                    severity = "HIGH"
                elif numeric >= 4:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                break
        return {
            "cve": ident,
            "package": package.get("name"),
            "version": package.get("version"),
            "severity": severity,
            "summary": vuln.get("summary") or vuln.get("details") or ident,
            "manifest": package.get("manifest"),
            "source": "osv",
            "aliases": aliases,
        }
