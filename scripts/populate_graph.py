#!/usr/bin/env python3
"""Push the current relational inventory into Neo4j (or report the memory fallback)."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
from api.graph_builder import sync_graph  # noqa: E402
from db.connection.session import SessionLocal, init_db  # noqa: E402


def main() -> int:
    init_db()
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
