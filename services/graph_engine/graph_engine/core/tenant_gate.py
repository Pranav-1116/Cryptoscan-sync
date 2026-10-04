"""Tenant-scope detection for the graph plane.

The graph engine keeps no tenant data of its own: callers build payloads from
tenant-filtered ORM rows (``api.graph_builder.collect_graph_payload``). The
Neo4j store the engine can delegate to, however, is process-global — it has
no notion of tenant ownership. While the database plane's tenant guard is
active, every Neo4j touch — read *or* write — must therefore be suppressed
and the request served from the in-process engine built off the scoped
payload instead.
"""

from __future__ import annotations

try:  # full-stack layout: the database plane ships the tenant guard
    from db.tenancy import isolation_active as _isolation_active
except ImportError:  # standalone graph-engine deployment: no tenant plane

    def _isolation_active() -> bool:  # pragma: no cover - standalone only
        return False


def tenant_isolated() -> bool:
    """True while a tenant scope is in force (and the guard is importable)."""
    return _isolation_active()
