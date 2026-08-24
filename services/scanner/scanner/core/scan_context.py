"""Metadata for one scanner run."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ScanContext:
    root_path: Path
    scan_id: str
    target_type: str = "LOCAL_DIRECTORY"
    target_location: str = ""
    target_commit: str | None = None
    target_branch: str | None = None
    languages: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    exclude_test_dirs: bool = False
