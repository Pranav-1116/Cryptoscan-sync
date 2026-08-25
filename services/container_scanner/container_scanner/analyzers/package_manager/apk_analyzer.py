"""Alpine apk installed-db parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from container_scanner.analyzers.package_manager.base_package_analyzer import BasePackageAnalyzer
from container_scanner.parsers.os_packages import parse_apk_installed


class ApkAnalyzer(BasePackageAnalyzer):
    manager = "apk"

    def matches(self, path: Path) -> bool:
        posix = path.as_posix()
        name = path.name.lower()
        return posix.endswith("/lib/apk/db/installed") or name in {"apk-installed", "installed"} and "apk" in posix

    def parse(self, path: Path) -> list[dict[str, Any]]:
        return parse_apk_installed(path)
