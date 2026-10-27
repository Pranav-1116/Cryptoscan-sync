"""Step 10: bank domain negatives and selected-query DOUBLE parity.

The fake driver does not execute Cypher. See the separately marked live gate.
Tenant-scoped API requests must never reach the global native backend.
"""

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from cbom.unified_cascade import unified_cascade
from db.tenancy import tenant_scope
from graph_engine.core.engine import GraphEngine
from graph_engine.core.facade import resolve_graph
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.core.sync_coordinator import sync_payload
from graph_engine.testing.fake_driver import FakeDriver

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def payload(mode="HARD", lifecycle=None, relation="CALLS"):
    assertion = {"mode": mode}
    if mode == "FAILOVER":
        assertion["failover_system_ids"] = ["alternative"]
    if mode == "ASYNC_BUFFERED":
        assertion["buffer_retention_seconds"] = 90
    return {
        "systems": [{"id": s, "name": s} for s in ("mobile", "payments", "ledger", "alternative", "isolated")],
        "edges": [
            {
                "parent_id": "mobile",
                "child_id": "payments",
                "relation": relation,
                "provenance": "DECLARED",
                "source": "bank-owner",
                "evidence_ref": "change/10",
                "operational_dependency": assertion,
                **(lifecycle or {}),
            },
            {"parent_id": "payments", "child_id": "ledger", "relation": "DEPENDS_ON"},
            {"parent_id": "ledger", "child_id": "payments", "relation": "DEPENDS_ON"},
        ],
        "processes": [
            {"id": "payments-process", "name": "Payments", "system_ids": ["payments", "mobile"], "revenue_daily": 100},
            {"id": "ledger-process", "name": "Payments", "system_ids": ["ledger"], "revenue_daily": 100},
        ],
    }


def answers(data):
    native = Neo4jGraphStore(FakeDriver(), now=NOW)
    native.sync(**data)
    graphs = [GraphEngine(now=NOW).build(**data), native]
    results = [g.business_impact("payments", hops=3) for g in graphs]
    registry = {}
    for p in data["processes"]:
        for sid in p["system_ids"]:
            registry.setdefault(sid, []).append({"id": p["id"], "name": p["name"], "revenue_daily": p["revenue_daily"]})
    snapshot = {
        "systems": data["systems"],
        "dependencies": [{**e, "source": e["parent_id"], "target": e["child_id"]} for e in data["edges"]],
        "business_processes": registry,
    }
    original = deepcopy(snapshot)
    unified = unified_cascade(snapshot, target="payments", kind="system", max_depth=3, now=NOW)
    assert original == snapshot
    results.append({**unified["impact"], "coverage": unified["coverage"]})
    return results


@pytest.mark.parametrize("mode", ["UNKNOWN", "HARD", "OPTIONAL", "FAILOVER", "ASYNC_BUFFERED"])
@pytest.mark.parametrize(
    "lifecycle,active",
    [
        ({}, True),
        ({"lifecycle_state": "STALE"}, False),
        ({"lifecycle_state": "UNKNOWN"}, False),
        ({"lifecycle_state": "DELETED"}, False),
        ({"lifecycle_state": "SUPERSEDED"}, False),
        ({"valid_until": NOW.isoformat()}, False),
        ({"valid_until": "not-a-date"}, False),
    ],
)
def test_modes_cannot_override_lifecycle_or_expand_failover_membership(mode, lifecycle, active):
    results = answers(payload(mode, lifecycle))
    for result in results:
        scope = result["system_classification"]
        assert scope["direct_exposure"]["systems"] == ["payments"]
        assert scope["dependent_consumers"]["systems"] == (["ledger", "mobile"] if active else ["ledger"])
        # ledger's reverse cycle is still modeled exposure, not supporting-only.
        assert "alternative" not in scope["review_systems"]
        assert "isolated" not in scope["review_systems"]
        if active:
            assert result["operational_impact"]["mode_counts"][mode] >= 1
        assert result["operational_impact"]["provider_disruption_assumed"] is False
        assert result["process_impact"]["counts"]["review"] == 2
        assert result["coverage"]["estate_completeness"] == "UNKNOWN"
    assert (
        results[0]["system_classification"]
        == results[1]["system_classification"]
        == results[2]["system_classification"]
    )
    assert (
        results[0]["operational_impact"]["mode_counts"]
        == results[1]["operational_impact"]["mode_counts"]
        == results[2]["operational_impact"]["mode_counts"]
    )
    assert results[1]["coverage"]["horizon_extension_unknown"]


@pytest.mark.parametrize("relation", ["USES", "SUPPORTS", "CONTAINS", "SECURED_BY", "CUSTOM_BANK_LINK"])
def test_business_context_relations_cannot_become_consumers_even_with_hard_mode(relation):
    for result in answers(payload(relation=relation)):
        assert "mobile" not in result["system_classification"]["review_systems"]
        assert result["operational_impact"]["mode_counts"]["HARD"] == 0


class NoBolt:
    def session(self, **kwargs):
        pytest.fail("A bank-scoped read/write must not probe or touch global Bolt")


@pytest.mark.parametrize("bank", ["bank-a", "bank-b"])
@pytest.mark.parametrize("mode", ["HARD", "OPTIONAL", "FAILOVER", "ASYNC_BUFFERED"])
def test_tenant_gate_covers_operational_process_evidence_and_coverage_surfaces(bank, mode):
    data = payload(mode)
    with tenant_scope(bank):
        graph = resolve_graph(data, driver=NoBolt())
        result = graph.business_impact("payments", hops=1)
        assert result["backend"] == "memory-tenant-isolated"
        assert result["process_impact"]["counts"]["review"] == 2
        assert result["operational_impact"]["mode_counts"][mode] >= 1
        assert result["coverage"]["estate_completeness"] == "UNKNOWN"
        assert sync_payload(data, driver=NoBolt())["synced"] is False


@pytest.mark.parametrize(
    "assertion",
    [
        {"mode": "GUARANTEED_SAFE"},
        {"mode": "ASYNC_BUFFERED", "buffer_retention_seconds": -1},
        {"mode": "HARD", "confidence": 1},
    ],
)
def test_malformed_declarations_never_acquire_hard_mode_or_remove_exposure(assertion):
    data = payload()
    data["edges"][0]["operational_dependency"] = assertion
    for result in answers(data):
        assert result["operational_impact"]["mode_counts"]["HARD"] == 0
        assert result["system_classification"]["exposure_system_count"] == 3


def _qualification_prefix():
    import uuid

    # Failover IDs must remain <=36 characters after appending the entity ID.
    return "b10" + uuid.uuid4().hex[:16]


def test_live_fixture_uses_valid_bounded_failover_identities():
    from shared_models.operational_dependencies import validate_assertion

    prefix = _qualification_prefix()
    ids = [prefix + "-" + sid for sid in ("payments", "alternative")]
    assert all(len(sid) <= 36 for sid in ids)
    assert validate_assertion({"mode": "FAILOVER", "failover_system_ids": ids})["mode"] == "FAILOVER"


@pytest.fixture()
def live_bank_graph():
    """Explicitly opted-in, empty disposable Neo4j only. Never a production DB.

    Missing configuration is a FAILURE when explicitly selecting the live gate,
    not a silent skip that could be mistaken for successful qualification.
    """
    import os
    from neo4j import GraphDatabase

    if os.environ.get("CRYPTOSCAN_TEST_NEO4J_DISPOSABLE") != "1":
        pytest.fail(
            "Live bank qualification requires an exclusive disposable empty Neo4j database and explicit DISPOSABLE=1 opt-in"
        )
    required = [
        "CRYPTOSCAN_TEST_NEO4J_URI",
        "CRYPTOSCAN_TEST_NEO4J_USER",
        "CRYPTOSCAN_TEST_NEO4J_PASSWORD",
        "CRYPTOSCAN_TEST_NEO4J_DATABASE",
    ]
    if not all(os.environ.get(key) for key in required):
        pytest.fail("Live Neo4j qualification configuration is incomplete; no connection attempted")
    database = os.environ[required[3]]
    driver = GraphDatabase.driver(os.environ[required[0]], auth=(os.environ[required[1]], os.environ[required[2]]))
    prefix = _qualification_prefix()
    admitted = False
    try:
        with driver.session(database=database) as session:
            if session.run("MATCH (n) RETURN count(n) AS count").single()["count"] != 0:
                pytest.fail("Refusing live bank qualification: database must be empty and dedicated")
        admitted = True
        yield driver, database, prefix
    finally:
        # Exact random-prefix match only: never a database-wide DETACH DELETE.
        # No sync/prune runs on a database that failed the empty precondition.
        try:
            if admitted:
                with driver.session(database=database) as session:
                    session.run(
                        "MATCH (n) WHERE n.system_id STARTS WITH $prefix OR n.process_id STARTS WITH $prefix DETACH DELETE n",
                        prefix=prefix,
                    ).consume()
        finally:
            driver.close()


@pytest.mark.live
@pytest.mark.parametrize(
    "mode,lifecycle",
    [
        ("HARD", {}),
        ("OPTIONAL", {}),
        ("FAILOVER", {"lifecycle_state": "STALE"}),
        ("ASYNC_BUFFERED", {}),
        ("HARD", {"lifecycle_state": "DELETED"}),
        ("HARD", {"valid_until": NOW.isoformat()}),
    ],
)
def test_live_native_bank_semantics_match_memory_on_disposable_database(live_bank_graph, mode, lifecycle):
    driver, database, prefix = live_bank_graph
    data = payload(mode, lifecycle)
    identity = lambda value: prefix + "-" + value
    for system in data["systems"]:
        system["id"] = identity(system["id"])
    for edge in data["edges"]:
        for field in ("parent_id", "child_id"):
            edge[field] = identity(edge[field])
        assertion = edge.get("operational_dependency") or {}
        if "failover_system_ids" in assertion:
            assertion["failover_system_ids"] = [identity(s) for s in assertion["failover_system_ids"]]
    for process in data["processes"]:
        process["id"] = identity(process["id"])
        process["system_ids"] = [identity(s) for s in process["system_ids"]]
    memory = GraphEngine(now=NOW).build(**data)
    native = Neo4jGraphStore(driver, database=database, now=NOW)
    native.sync(**data)
    expected = memory.business_impact(identity("payments"))
    actual = native.business_impact(identity("payments"))
    assert actual["system_classification"] == expected["system_classification"]
    assert actual["process_impact"]["counts"] == expected["process_impact"]["counts"]
    assert actual["operational_impact"]["mode_counts"] == expected["operational_impact"]["mode_counts"]
    assert actual["coverage"]["horizon_extension_unknown"]
