"""Dependency graph: Neo4j when configured, in-process otherwise."""

from graph_engine.core.engine import GraphEngine
from graph_engine.core.facade import graph_health, memory_graph, resolve_graph
from graph_engine.core.store import Neo4jGraphStore

__all__ = ["GraphEngine", "Neo4jGraphStore", "graph_health", "memory_graph", "resolve_graph"]
