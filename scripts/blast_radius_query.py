#!/usr/bin/env python3
"""CLI blast-radius query against Neo4j or the in-process graph."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from api.graph_builder import graph_from_db  # noqa: E402
from db.connection.session import SessionLocal  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("system_id")
    parser.add_argument("--hops", type=int, default=5)
    parser.add_argument("--impact", action="store_true")
    args = parser.parse_args()
    session = SessionLocal()
    try:
        graph = graph_from_db(session)
        payload = graph.business_impact(args.system_id, hops=args.hops) if args.impact else graph.blast_radius(
            args.system_id, hops=args.hops
        )
    finally:
        session.close()
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
