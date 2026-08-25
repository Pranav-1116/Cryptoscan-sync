"""Network-scan runtime context."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanContext:
    target: str
    target_kind: str = "filesystem"
    live: bool = False
    timeout: float = 5.0
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=_now)

    @classmethod
    def for_path(cls, root: str, **kwargs: Any) -> "ScanContext":
        return cls(target=str(root), target_kind="filesystem", **kwargs)

    @classmethod
    def for_hosts(cls, endpoint: str, **kwargs: Any) -> "ScanContext":
        return cls(target=str(endpoint), target_kind="hosts", **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


NetworkScanContext = ScanContext
