"""Sync business processes → graph."""

from __future__ import annotations

from typing import Any, Iterable

from graph_engine.builders.node_builder import NodeBuilder
from graph_engine.core.engine import GraphEngine


def sync_business_processes(
    processes: Iterable[dict[str, Any]],
    *,
    engine: GraphEngine | None = None,
) -> GraphEngine:
    builder = NodeBuilder(engine)
    return builder.build(processes=processes)
