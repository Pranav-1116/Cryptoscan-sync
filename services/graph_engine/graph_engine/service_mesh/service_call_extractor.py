"""Normalize service-mesh rows into GraphEngine / Neo4j CALLS edges."""

from __future__ import annotations

from typing import Any, Iterable


def extract_calls(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    edges = []
    for row in rows:
        parent = row.get("parent_id") or row.get("source") or row.get("source_workload")
        child = row.get("child_id") or row.get("destination") or row.get("destination_workload")
        if not parent or not child:
            continue
        edges.append(
            {
                "parent_id": str(parent),
                "child_id": str(child),
                "protocol": row.get("protocol") or "mesh",
                "frequency": row.get("frequency") or row.get("request_count"),
                "relation": "CALLS",
                "data_source": row.get("data_source") or "service-mesh",
            }
        )
    return edges
