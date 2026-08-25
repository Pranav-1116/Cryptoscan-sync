"""Merge local CVE rows with live OSV / NVD lookups. Fail-open."""

from __future__ import annotations

import logging
import os
from typing import Any, Iterable

from container_scanner.core.versioning import version_matches
from container_scanner.cve.nvd import NvdClient
from container_scanner.cve.osv import OsvClient

logger = logging.getLogger(__name__)


def live_cve_enabled(override: bool | None = None) -> bool:
    if override is not None:
        return override
    raw = os.environ.get("CRYPTOSCAN_CVE_LIVE", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


class VulnerabilityResolver:
    def __init__(
        self,
        local_db: dict[str, Any] | None = None,
        *,
        live: bool | None = None,
        osv: OsvClient | None = None,
        nvd: NvdClient | None = None,
    ):
        self.local_db = local_db or {}
        self.live = live_cve_enabled(live)
        self.osv = osv or OsvClient()
        self.nvd = nvd or NvdClient()

    def lookup(self, packages: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        items = list(packages)
        found: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()

        def add(row: dict[str, Any]) -> None:
            key = (
                str(row.get("cve") or ""),
                str(row.get("package") or "").lower(),
                str(row.get("version") or ""),
            )
            if not key[0] or key in seen:
                return
            seen.add(key)
            found.append(row)

        for package in items:
            for row in self._local_matches(package):
                add(row)

        if self.live and items:
            try:
                for row in self.osv.query_batch(items):
                    add(row)
            except Exception as exc:
                logger.info("live_osv_skipped", extra={"error": str(exc)})
            if self.nvd.enabled:
                for package in items:
                    try:
                        for row in self.nvd.lookup(package):
                            add(row)
                    except Exception as exc:
                        logger.info("live_nvd_skipped", extra={"error": str(exc)})
        return found

    def _local_matches(self, package: dict[str, Any]) -> list[dict[str, Any]]:
        name = (package.get("name") or "").lower()
        version = package.get("version")
        matches = []
        for advisory in self.local_db.get("advisories") or []:
            if str(advisory.get("package") or "").lower() != name:
                continue
            if version_matches(version, str(advisory.get("affected") or "*")):
                matches.append(
                    {
                        "cve": advisory.get("cve"),
                        "package": name,
                        "version": version,
                        "severity": advisory.get("severity"),
                        "summary": advisory.get("summary"),
                        "manifest": package.get("manifest"),
                        "source": "local",
                    }
                )
        return matches
