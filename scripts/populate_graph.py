#!/usr/bin/env python3
"""Push the current relational inventory into Neo4j (or report the memory fallback)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for extra in (
    ROOT / "services" / "api",
    ROOT / "services" / "database",
    ROOT / "services" / "graph_engine",
    ROOT / "services" / "business_context",
    ROOT / "shared" / "shared_config",
):
    sys.path.insert(0, str(extra))

from api.graph_builder import sync_graph  # noqa: E402
from db.connection.session import SessionLocal  # noqa: E402


def main() -> int:
    session = SessionLocal()
    try:
        result = sync_graph(session)
    finally:
        session.close()
    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0 if result.get("backend") else 1


if __name__ == "__main__":
    raise SystemExit(main())
