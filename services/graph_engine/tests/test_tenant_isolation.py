"""Tenant isolation on the graph plane.

The Neo4j store is process-global: it has no tenant property on its nodes
and serves every query from the same graph. Before the isolation gate, a
tenant-scoped request with a healthy Bolt connection was handed that global
store for *every* /graph route (blast radius, hotspots, vendor chains...),
and a scoped ``sync`` wrote the tenant's inventory into it — a full
cross-tenant read and write hole. The facade now refuses to touch the driver
at all while a tenant scope is active and serves the (tenant-filtered,
ORM-built) payload on the in-process engine instead.

These tests pin that property with a recording fake driver: a scoped call
must issue **zero** Bolt statements, healthy or not.
"""

from __future__ import annotations

import importlib

import pytest

from db.tenancy import install_tenant_guard, tenant_scope
from graph_engine.core.engine import GraphEngine
from graph_engine.core.facade import resolve_graph
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.core import sync_coordinator, tenant_gate
from graph_engine.core.sync_coordinator import ensure_populated, sync_payload

BANK_A = "11111111-1111-1111-1111-111111111111"
BANK_B = "22222222-2222-2222-2222-222222222222"

PAYLOAD_A = {
    "systems": [
        {"id": "sys-a", "name": "Bank A core", "environment": "prod"},
        {"id": "sys-a-dep", "name": "Bank A dependency", "environment": "prod"},
    ],
    "assets": [{"id": "asset-a", "system_id": "sys-a", "algorithm": "RSA-2048"}],
    "edges": [{"parent_id": "sys-a", "child_id": "sys-a-dep", "relation": "CALLS"}],
}
PAYLOAD_B = {
    "systems": [{"id": "sys-b", "name": "Bank B trading", "environment": "prod"}],
    "assets": [{"id": "asset-b", "system_id": "sys-b", "algorithm": "ECDSA-P256"}],
}


class FakeRecord:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getitem__(self, key):
        return self._data[key]


class FakeResult:
    def __init__(self, data):
        self._data = data

    def single(self):
        return FakeRecord(self._data) if self._data else None

    def __iter__(self):
        return iter([FakeRecord(self._data)] if self._data else [])


class FakeSession:
    def __init__(self, log, healthy=True):
        self._log = log
        self._healthy = healthy

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def close(self):
        return None

    def run(self, query, *args, **kwargs):
        self._log.append(query)
        if "RETURN 1" in query:  # the PING health probe
            return FakeResult({"ok": 1} if self._healthy else {"ok": 0})
        return FakeResult({"nodes": 999, "edges": 999})


class FakeDriver:
    """Records every Bolt statement; can pretend to be healthy."""

    def __init__(self, healthy=True):
        self.log: list[str] = []
        self._healthy = healthy

    def session(self, database=None):
        return FakeSession(self.log, healthy=self._healthy)


@pytest.fixture(autouse=True)
def _guard():
    install_tenant_guard()


# --------------------------------------------------------------------- #
# reads: a scoped request must never touch the driver
# --------------------------------------------------------------------- #

def test_scoped_resolve_graph_ignores_a_healthy_neo4j():
    driver = FakeDriver(healthy=True)
    with tenant_scope(BANK_A):
        graph = resolve_graph(PAYLOAD_A, driver=driver)
    assert isinstance(graph, GraphEngine)
    assert graph.backend == "memory-tenant-isolated"
    assert driver.log == [], "a tenant-scoped resolve must issue zero Bolt statements"


def test_scoped_resolve_graph_serves_exactly_the_payload_it_was_given():
    """The graph layer has no tenant knowledge of its own: isolation is
    (ORM-filtered payload) + (never touching the global store). Given the
    payload the ORM produces under scope A, it serves exactly that slice."""
    driver = FakeDriver(healthy=True)
    with tenant_scope(BANK_A):
        graph_a = resolve_graph(PAYLOAD_A, driver=driver)
    assert set(graph_a.nodes) == {"system:sys-a", "system:sys-a-dep", "asset:asset-a"}
    with tenant_scope(BANK_B):
        graph_b = resolve_graph(PAYLOAD_B, driver=driver)
    assert set(graph_b.nodes) == {"system:sys-b", "asset:asset-b"}
    # The end-to-end proof (ORM payload really is tenant-filtered) lives in
    # the API adversarial suite: services/api/tests/security/.


def test_scoped_blast_radius_runs_on_the_isolated_engine():
    driver = FakeDriver(healthy=True)
    with tenant_scope(BANK_A):
        graph = resolve_graph(PAYLOAD_A, driver=driver)
        result = graph.blast_radius("system:sys-a", hops=2)
    assert result["backend"] == "memory-tenant-isolated"
    assert driver.log == []


def test_unscoped_resolve_graph_uses_a_healthy_neo4j():
    driver = FakeDriver(healthy=True)
    graph = resolve_graph(PAYLOAD_A, driver=driver)
    assert isinstance(graph, Neo4jGraphStore)
    assert driver.log, "an unscoped resolve with healthy Bolt should use Neo4j"


def test_tenant_gate_is_inert_without_an_active_scope():
    driver = FakeDriver(healthy=True)
    assert not tenant_gate.tenant_isolated()
    graph = resolve_graph(PAYLOAD_A, driver=driver)
    assert isinstance(graph, Neo4jGraphStore)


# --------------------------------------------------------------------- #
# writes: a scoped sync must never seed the global store
# --------------------------------------------------------------------- #

def test_scoped_sync_payload_never_writes_neo4j():
    driver = FakeDriver(healthy=True)
    with tenant_scope(BANK_A):
        result = sync_payload(PAYLOAD_A, driver=driver)
    assert result["backend"] == "memory"
    assert result["synced"] is False
    assert result["reason"] == "tenant_isolated"
    assert result["nodes"] == len(resolve_graph(PAYLOAD_A).nodes)  # scoped counts only
    assert driver.log == [], "a tenant-scoped sync must issue zero Bolt statements"


def test_scoped_ensure_populated_does_not_seed_the_shared_store():
    driver = FakeDriver(healthy=True)
    with tenant_scope(BANK_A):
        result = ensure_populated(PAYLOAD_A, driver=driver)
    assert result["reason"] == "tenant_isolated"
    assert driver.log == []


def test_unscoped_sync_payload_writes_neo4j():
    driver = FakeDriver(healthy=True)
    result = sync_payload(PAYLOAD_A, driver=driver)
    assert result["synced"] is True
    assert driver.log, "an unscoped sync with a driver should write to Neo4j"


# --------------------------------------------------------------------- #
# standalone deployments: no database plane, no isolation semantics
# --------------------------------------------------------------------- #

def test_missing_db_plane_falls_back_to_global_behaviour(monkeypatch):
    """A graph engine deployed without the db package stays global by design."""
    import sys

    monkeypatch.setitem(sys.modules, "db.tenancy", None)  # forces ImportError
    try:
        reloaded = importlib.reload(tenant_gate)
        assert not reloaded.tenant_isolated()
        # Even with a scope active in the (unimportable) guard, the graph
        # plane cannot know about it: standalone means global by definition.
        driver = FakeDriver(healthy=True)
        graph = reloaded and resolve_graph(PAYLOAD_A, driver=driver)
        assert isinstance(graph, Neo4jGraphStore)
    finally:
        monkeypatch.undo()
        importlib.reload(tenant_gate)  # restore the real module for other tests


def test_sync_coordinator_module_contract_after_reload():
    """Reload must not have damaged the module the rest of the suite uses."""
    assert callable(sync_coordinator.sync_payload)
    assert callable(sync_coordinator.ensure_populated)
