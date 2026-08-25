"""Run package-manager, language-manifest, and OS analyzers over a rootfs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from container_scanner.analyzers.package_manager.apk_analyzer import ApkAnalyzer
from container_scanner.analyzers.package_manager.dpkg_analyzer import DpkgAnalyzer
from container_scanner.analyzers.package_manager.rpm_analyzer import RpmAnalyzer
from container_scanner.parsers.os_packages import parse_site_packages
from container_scanner.parsers.package_parsers import (
    parse_composer,
    parse_csproj,
    parse_cargo,
    parse_gemfile,
    parse_gomod,
    parse_package_json,
    parse_pom,
    parse_requirements,
)

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    "proc",
    "sys",
    "dev",
    "run",
}


class AnalyzerCoordinator:
    def __init__(self) -> None:
        self.os_analyzers = [DpkgAnalyzer(), RpmAnalyzer(), ApkAnalyzer()]

    def discover_packages(self, root: Path) -> list[dict[str, Any]]:
        files = list(self._iter_files(root))
        packages: list[dict[str, Any]] = []
        for path in files:
            name = path.name.lower()
            posix = path.as_posix()
            if name == "requirements.txt":
                packages.extend(parse_requirements(path))
            elif name == "package.json":
                packages.extend(parse_package_json(path))
            elif name == "pom.xml":
                packages.extend(parse_pom(path))
            elif name.endswith(".csproj"):
                packages.extend(parse_csproj(path))
            elif name == "go.mod":
                packages.extend(parse_gomod(path))
            elif name == "composer.json":
                packages.extend(parse_composer(path))
            elif name in {"gemfile", "gemfile.lock"}:
                packages.extend(parse_gemfile(path))
            elif name == "cargo.toml":
                packages.extend(parse_cargo(path))
            elif posix.endswith("/var/lib/dpkg/status") or name == "dpkg-status":
                packages.extend(DpkgAnalyzer().parse(path))
            elif posix.endswith("/lib/apk/db/installed") or name in {"apk-installed", "installed"}:
                if "apk" in posix or name == "apk-installed":
                    packages.extend(ApkAnalyzer().parse(path))
            elif name in {"rpm-packages.txt", "rpm-qa.txt"}:
                packages.extend(RpmAnalyzer().parse(path))
        packages.extend(parse_site_packages(root))
        return packages

    def _iter_files(self, root: Path) -> Iterable[Path]:
        for path in root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            yield path
