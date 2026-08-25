"""Sync crypto_assets → graph."""

from __future__ import annotations

from typing import Any, Iterable

from graph_engine.builders.node_builder import NodeBuilder
from graph_engine.core.engine import GraphEngine


def sync_crypto_assets(assets: Iterable[dict[str, Any]], *, engine: GraphEngine | None = None) -> GraphEngine:
    builder = NodeBuilder(engine)
    builder.add_assets(assets)
    return builder.engine
