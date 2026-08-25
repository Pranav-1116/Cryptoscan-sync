from graph_engine.builders.relationship_builder import RelationshipBuilder
from graph_engine.builders.crypto_asset_syncer import sync_crypto_assets
from graph_engine.builders.system_syncer import sync_systems
from graph_engine.core.engine import GraphEngine
from graph_engine.service_mesh.mesh_poller import poll_mesh


def test_relationship_builder_and_syncers():
    engine = GraphEngine()
    sync_systems([{"id": "pay", "name": "payments"}], engine=engine)
    sync_crypto_assets([{"id": "a1", "algorithm": "AES", "system_id": "pay"}], engine=engine)
    rel = RelationshipBuilder(engine)
    rel.calls("pay", "db")
    rel.supports("pay", "checkout")
    engine.add_node("process:checkout", kind="BusinessProcess", name="checkout", revenue_daily=10, customer_count=2)
    radius = engine.blast_radius("pay", hops=2)
    assert any(row["id"] == "db" for row in radius["systems"])
    edges = poll_mesh(raw=[{"source_workload": "pay", "destination_workload": "db", "frequency": 9}])
    assert edges[0]["parent_id"] == "pay"
