"""Build CycloneDX metadata for a CBOM."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


def build_metadata(
    *,
    name: str = "cryptoscan-target",
    version: str = "unknown",
    tool_version: str = "1.0.0",
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": {"type": "application", "name": name, "version": version},
        "tools": [{"name": "CryptoScan", "version": tool_version}],
        "serialNumber": f"urn:uuid:{hashlib.sha256(name.encode()).hexdigest()[:32]}",
    }
