"""Pick Neo4j when Bolt is healthy, otherwise the in-process engine."""

from __future__ import annotations

from typing import Any

from graph_engine.config.settings import get_graph_settings
from graph_engine.connection.health_check import probe_neo4j
from graph_engine.connection.neo4j_driver import get_driver
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.core.sync_coordinator import ensure_populated
from graph_engine.core.tenant_gate import tenant_isolated


def memory_graph(**payload) -> GraphEngine:
    return GraphEngine().build(**payload)


def resolve_graph(payload: dict[str, Any], *, driver=None, sync_if_empty: bool = True):
    if tenant_isolated():
        # The Neo4j store is process-global: it holds every tenant's nodes
        # and has no tenant filter, so serving it to a scoped request would
        # leak other tenants' inventories through every /graph route. Serve
        # the tenant-filtered payload on the in-process engine instead. The
        # driver is deliberately not even probed — a healthy Bolt must not
        # change the answer for a tenant.
        engine = memory_graph(**payload)
        engine.backend = "memory-tenant-isolated"
        return engine
    handle = driver if driver is not None else get_driver()
    health = probe_neo4j(handle)
    if handle is not None and health.get("ok"):
        store = Neo4jGraphStore(handle)
        if sync_if_empty:
            ensure_populated(payload, driver=handle)
        # Never serve an older ACTIVE projection after SQL has retired it.
        # Errors propagate rather than silently substituting an old answer.
        store.refresh_relationship_lifecycle(payload.get("systems") or [], payload.get("edges") or [])
        return store
    return memory_graph(**payload)


def graph_health(driver=None) -> dict[str, Any]:
    health = probe_neo4j(driver)
    settings = get_graph_settings()
    health["fallback"] = not health.get("ok")
    health["required"] = settings.NEO4J_REQUIRED
    return health
