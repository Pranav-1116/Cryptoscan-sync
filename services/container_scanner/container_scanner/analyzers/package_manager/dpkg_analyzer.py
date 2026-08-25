"""Debian/Ubuntu dpkg status parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from container_scanner.analyzers.package_manager.base_package_analyzer import BasePackageAnalyzer
from container_scanner.parsers.os_packages import parse_dpkg_status


class DpkgAnalyzer(BasePackageAnalyzer):
    manager = "dpkg"

    def matches(self, path: Path) -> bool:
        posix = path.as_posix()
        name = path.name.lower()
        return posix.endswith("/var/lib/dpkg/status") or name in {"dpkg-status", "status"} and "dpkg" in posix

    def parse(self, path: Path) -> list[dict[str, Any]]:
        return parse_dpkg_status(path)
