"""Multi-cloud scan orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloud_scanner.core.scanner import CloudScanner


def scan_all(
    root: str | Path | None = None,
    *,
    live: bool | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    scanner = CloudScanner(live=live)
    if root:
        return scanner.scan_filesystem(root, scan_id=scan_id)
    if not scanner.live:
        return {"scan_id": scan_id, "live": False, "findings": [], "resources": 0, "issues": 0, "providers": []}
    return scanner.scan_filesystem(".", scan_id=scan_id)
