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
        algorithms = list((info or {}).get("algorithms") or [])
        string_hits = _jar_string_hits(path, root)
        for hit in string_hits:
            algo = hit.get("algorithm")
            if algo and algo not in algorithms:
                algorithms.append(algo)
        entry = {
            "type": "jar",
            "name": path.stem.lower(),
            "path": str(path.relative_to(root)),
            "library": (info or {}).get("vendor") and repo.canonical(path.name),
            "algorithms": algorithms,
        }
        if string_hits:
            entry["string_hits"] = string_hits
        findings.append(entry)
    return findings


def _jar_string_hits(path: Path, root: Path) -> list[dict[str, Any]]:
    try:
        from scanner.detectors.java.jar_string_scanner import scan_jar
    except Exception:
        return []
    hits: list[dict[str, Any]] = []
    try:
        for finding in scan_jar(path, repo_root=root):
            hits.append(
                {
                    "path": getattr(getattr(finding, "source", None), "file_path", None),
                    "algorithm": getattr(getattr(finding, "crypto", None), "algorithm", None),
                    "snippet": getattr(getattr(finding, "source", None), "code_snippet", None),
                }
            )
    except Exception:
        return []
    return hits
