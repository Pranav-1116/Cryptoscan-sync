"""Scan site-packages metadata inside a container root."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from container_scanner.parsers.os_packages import parse_site_packages


def scan_site_packages(root: Path) -> list[dict[str, Any]]:
    return parse_site_packages(root)
