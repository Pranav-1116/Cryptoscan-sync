from graph_engine.queries import BLAST_RADIUS, VENDOR_PATH
from graph_engine.queries.business_impact import PROCESS_LINKS
from graph_engine.queries.blast_radius import ORIGIN_SYSTEM, SYSTEMS_USING_ASSET
from graph_engine.testing.fake_driver import query_name


def test_queries_are_tagged_cypher():
    assert query_name(BLAST_RADIUS) == "blast_radius"
    assert "[:CALLS*1..12]" in BLAST_RADIUS
    assert "downstream:System" in BLAST_RADIUS
    assert "BusinessProcess" in PROCESS_LINKS
    # Minimize after filtering the system prefix and final vendor linkage.
    assert "[:CALLS*0..12]" in VENDOR_PATH
    assert "ORDER BY hops, vendor_id" in VENDOR_PATH
    assert "DEPENDS_ON_VENDOR" in VENDOR_PATH
    assert query_name(ORIGIN_SYSTEM) == "origin_system"
    assert query_name(SYSTEMS_USING_ASSET) == "systems_using_asset"
