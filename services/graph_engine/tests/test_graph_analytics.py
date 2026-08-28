"""Graph analytics: dependency cycles (SCC), certificate exposure, graph stats."""

from __future__ import annotations

from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.testing.fake_driver import FakeDriver


def _payload():
    return dict(
        systems=[
            {"id": "web", "name": "web-frontend"},
            {"id": "pay", "name": "payment-api", "criticality": "TIER-1"},
            {"id": "db", "name": "customer-db"},
            {"id": "mail", "name": "email-service"},       # acyclic leaf
            {"id": "cache", "name": "redis-cache"},        # self-loop below
            {"id": "lonely", "name": "forgotten-service"}, # orphan: no calls, no assets
        ],
        assets=[
            {"id": "a1", "algorithm": "RSA-2048", "system_id": "pay", "confidence": "HIGH"},
            {"id": "a2", "algorithm": "AES-256-GCM", "system_id": "db", "confidence": "HIGH"},
            {"id": "a-free", "algorithm": "DES", "confidence": "LOW"},  # unlinked asset
        ],
        edges=[
            {"parent_id": "web", "child_id": "pay", "relation": "CALLS"},
            {"parent_id": "pay", "child_id": "db", "relation": "CALLS"},
            {"parent_id": "db", "child_id": "web", "relation": "CALLS"},   # cycle web->pay->db->web
            {"parent_id": "pay", "child_id": "mail", "relation": "CALLS"},
            {"parent_id": "cache", "child_id": "cache", "relation": "CALLS"},  # self-call
        ],
        processes=[
            {"id": "bp1", "name": "Payment Processing", "revenue_daily": 2_100_000, "customer_count": 1_800_000, "system_ids": ["pay"]},
        ],
        certificates=[
            {"id": "c-exp", "subject": "CN=payment-api", "expiry_status": "EXPIRING_30D", "not_after": "2026-09-15", "system_ids": ["pay"]},
            {"id": "c-ok", "subject": "CN=customer-db", "expiry_status": "VALID", "not_after": "2027-01-01", "system_ids": ["db"]},
            {"id": "c-dead", "subject": "CN=legacy", "expiry_status": "EXPIRED", "system_ids": ["mail"]},
            {"id": "c-unknown", "subject": "CN=mystery", "system_ids": ["web"]},  # no status -> unknown count
        ],
    )


def _store():
    store = Neo4jGraphStore(FakeDriver(), database="neo4j")
    store.sync(**_payload())
    return store


# --------------------------------------------------------------------------- #
# cycles
# --------------------------------------------------------------------------- #

def test_memory_finds_scc_cycle_and_self_loop():
    result = GraphEngine().build(**_payload()).find_cycles()
    assert result["count"] == 2
    scc = next(c for c in result["cycles"] if c["size"] == 3)
    assert scc["members"] == ["system:db", "system:pay", "system:web"]
    assert set(scc["member_names"]) == {"web-frontend", "payment-api", "customer-db"}
    self_loop = next(c for c in result["cycles"] if c["self_loop"])
    assert self_loop["members"] == ["system:cache"] and self_loop["size"] == 1
    assert "system:mail" not in result["systems_in_cycles"]  # acyclic leaf
    assert set(result["systems_in_cycles"]) == {"system:web", "system:pay", "system:db", "system:cache"}


def test_store_finds_cycles_via_export_vis():
    result = _store().find_cycles()
    assert result["backend"] == "neo4j"
    assert result["count"] == 2
    assert {"system:db", "system:pay", "system:web"} in [set(c["members"]) for c in result["cycles"] if c["size"] == 3]


def test_cycles_empty_graph_is_zero():
    result = GraphEngine().find_cycles()
    assert result["count"] == 0 and result["cycles"] == [] and result["systems_in_cycles"] == []


# --------------------------------------------------------------------------- #
# certificate exposure
# --------------------------------------------------------------------------- #

def test_memory_certificate_exposure_ranks_by_revenue():
    result = GraphEngine().build(**_payload()).certificate_exposure()
    at_risk = result["at_risk"]
    assert [row["cert_id"] for row in at_risk] == ["c-exp", "c-dead"]  # revenue desc, then id
    top = at_risk[0]
    assert top["expiry_status"] == "EXPIRING_30D"
    assert top["systems"] == [{"id": "pay", "name": "payment-api", "criticality": "TIER-1"}]
    assert top["revenue_daily_at_risk"] == 2_100_000
    assert top["customers_at_risk"] == 1_800_000
    dead = at_risk[1]
    assert dead["systems"][0]["id"] == "mail" and dead["revenue_daily_at_risk"] == 0
    totals = result["totals"]
    assert totals["certs_at_risk"] == 2
    assert totals["healthy_certs"] == 1
    assert totals["certs_unknown_status"] == 1  # honest: no status is not "fine"
    assert totals["systems_affected"] == 2
    assert totals["revenue_daily_at_risk"] == 2_100_000
    assert totals["by_status"] == {"EXPIRED": 1, "EXPIRING_30D": 1, "VALID": 1}


def test_store_certificate_exposure_via_export_vis():
    result = _store().certificate_exposure()
    assert result["backend"] == "neo4j"
    assert result["totals"]["certs_at_risk"] == 2
    assert result["at_risk"][0]["cert_id"] == "c-exp"


def test_certificate_exposure_no_certs():
    result = GraphEngine().build(systems=[{"id": "a", "name": "solo"}]).certificate_exposure()
    assert result["at_risk"] == []
    assert result["totals"]["certs_at_risk"] == 0


# --------------------------------------------------------------------------- #
# graph stats
# --------------------------------------------------------------------------- #

def test_memory_graph_stats_counts_and_hygiene():
    result = GraphEngine().build(**_payload()).graph_stats()
    assert result["nodes_by_kind"]["System"] == 6
    assert result["nodes_by_kind"]["CryptoAsset"] == 3
    assert result["nodes_by_kind"]["Certificate"] == 4
    assert result["nodes_by_kind"]["BusinessProcess"] == 1
    assert result["edges_by_relation"]["CALLS"] == 5
    assert result["edges_by_relation"]["USES"] == 2
    assert result["edges_by_relation"]["SECURED_BY"] == 4
    assert result["edges_by_relation"]["SUPPORTS"] == 1
    assert result["orphan_systems"] == ["system:lonely"]
    assert result["unlinked_assets"] == ["asset:a-free"]
    assert result["max_out_degree"]["id"] == "system:pay"  # USES + 2x CALLS + SUPPORTS + SECURED_BY
    assert result["max_out_degree"]["degree"] == 5


def test_store_graph_stats_via_export_vis():
    result = _store().graph_stats()
    assert result["backend"] == "neo4j"
    assert result["systems"] == 6
    assert result["orphan_systems"] == ["system:lonely"]
    assert result["unlinked_assets"] == ["asset:a-free"]


def test_graph_stats_empty():
    result = GraphEngine().graph_stats()
    assert result["nodes"] == 0 and result["edges"] == 0
    assert result["max_out_degree"] is None
    assert result["orphan_systems"] == [] and result["unlinked_assets"] == []
