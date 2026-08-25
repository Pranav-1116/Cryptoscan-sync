"""RHEL/CentOS/Fedora rpm -qa text parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from container_scanner.analyzers.package_manager.base_package_analyzer import BasePackageAnalyzer
from container_scanner.parsers.os_packages import parse_rpm_qa


class RpmAnalyzer(BasePackageAnalyzer):
    manager = "rpm"

    def matches(self, path: Path) -> bool:
        return path.name.lower() in {"rpm-packages.txt", "rpm-qa.txt"}

    def parse(self, path: Path) -> list[dict[str, Any]]:
        return parse_rpm_qa(path)
