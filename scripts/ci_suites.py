#!/usr/bin/env python3
"""Discover backend CI suites from the checkout, without importing the application.

The main gate must cover services AND shared packages. Stop at each outermost
``tests`` directory, so a nested fixture cannot schedule the same tests twice.
JSON is suitable for GitHub Actions' fromJSON matrix; no dependencies required.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

SCANNERS = frozenset({"scanner", "network_scanner", "cloud_scanner", "container_scanner", "universal_vendor"})
IGNORED = frozenset({"node_modules", "__pycache__", ".venv", "venv", "build", "dist"})


def discover_suites(root: Path, *, scanners_only: bool = False) -> list[str]:
    root = root.resolve()
    suites = []
    for area in ("services", "shared"):
        base = root / area
        if not base.is_dir():
            raise ValueError(f"missing suite root: {area}")
        for current, dirs, _files in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in IGNORED
                             and not (Path(current) / d).is_symlink())
            current_path = Path(current)
            if current_path.name != "tests":
                continue
            relative = current_path.relative_to(root)
            dirs.clear()
            if scanners_only and (area != "services" or relative.parts[1] not in SCANNERS):
                continue
            suite = relative.as_posix()
            # Matrix values become filesystem arguments. Refuse surprising names
            # instead of allowing shell metacharacters or ambiguous output lines.
            if not re.fullmatch(r"(?:[A-Za-z0-9_-]+/)+tests", suite):
                raise ValueError(f"unsafe test suite path: {suite!r}")
            suites.append(suite)
    if not suites:
        raise ValueError("no backend test suites discovered")
    if len(suites) > 256:
        raise ValueError("backend matrix exceeds GitHub's 256-job limit; introduce explicit sharding")
    return sorted(suites)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--scanners-only", action="store_true")
    args = parser.parse_args()
    try:
        suites = discover_suites(args.root, scanners_only=args.scanners_only)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps({"include": [{"suite": suite} for suite in suites]}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
