"""Find JARs in a container root and emit library fingerprints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from container_scanner.analyzers.binary.shared_library_finder import find_jars
from container_scanner.fingerprints.repository import FingerprintRepository


def scan_jars(root: Path, catalog: FingerprintRepository | None = None) -> list[dict[str, Any]]:
    repo = catalog or FingerprintRepository()
    findings: list[dict[str, Any]] = []
    for path in find_jars(root):
        info = repo.match_binary(path.name) or repo.lookup(path.stem)
        findings.append(
            {
                "type": "jar",
                "name": path.stem.lower(),
                "path": str(path.relative_to(root)),
                "library": (info or {}).get("vendor") and repo.canonical(path.name),
                "algorithms": list((info or {}).get("algorithms") or []),
            }
        )
    return findings
