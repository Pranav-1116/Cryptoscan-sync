#!/usr/bin/env python3
"""Print the registered DiscoveryPlugin catalog."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [
    str(ROOT / "services" / "scanner"),
    str(ROOT / "shared" / "shared_models"),
]


def main(argv: list[str] | None = None) -> int:
    from scanner.core.plugin import plugin_catalog

    payload = {"plugins": plugin_catalog()}
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
