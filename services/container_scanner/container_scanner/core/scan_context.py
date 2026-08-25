"""Container-scan runtime context (distinct from static scanner ScanContext)."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanContext:
    target: str
    target_kind: str = "filesystem"
    live_cve: bool = False
    workdir: str | None = None
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=_now)

    @classmethod
    def for_path(cls, root: str | Path, **kwargs: Any) -> "ScanContext":
        return cls(target=str(root), target_kind="filesystem", **kwargs)

    @classmethod
    def for_image(cls, reference: str, **kwargs: Any) -> "ScanContext":
        return cls(target=str(reference), target_kind="image", **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
