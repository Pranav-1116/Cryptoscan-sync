"""Load YAML/JSON TLS scan targets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_targets(path: str | Path) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.is_file():
        return []
    data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    if isinstance(data, list):
        rows = data
    else:
        rows = data.get("targets") or data.get("endpoints") or []
    targets = []
    for item in rows:
        if isinstance(item, str):
            targets.append({"endpoint": item, "scan_frequency": "daily", "enabled": True})
            continue
        if not isinstance(item, dict):
            continue
        endpoint = item.get("endpoint") or item.get("host")
        if not endpoint:
            continue
        targets.append(
            {
                "endpoint": str(endpoint),
                "system_id": item.get("system_id"),
                "scan_frequency": item.get("scan_frequency") or "daily",
                "enabled": item.get("enabled", True),
            }
        )
    return targets
