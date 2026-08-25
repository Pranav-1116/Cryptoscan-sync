"""Generic neighbourhood dump used by the dashboard canvas."""

from __future__ import annotations

EXPORT_VIS = """
// cryptoscan.query=export_vis
MATCH (n)
OPTIONAL MATCH (n)-[r]->(m)
RETURN n, r, m
"""

COUNT_NODES = """
// cryptoscan.query=count_nodes
MATCH (n) RETURN count(n) AS nodes
"""

COUNT_EDGES = """
// cryptoscan.query=count_edges
MATCH ()-[r]->() RETURN count(r) AS edges
"""

PING = """
// cryptoscan.query=ping
RETURN 1 AS ok
"""
