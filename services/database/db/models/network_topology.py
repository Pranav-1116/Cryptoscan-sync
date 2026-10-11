"""Declared network topology (advanced/58 P0#1–2, round 31).

The platform does not have a live topology feed (cloud APIs, K8s API),
and report 58 correctly kept NetworkEdge/LoadBalancer nodes and
TERMINATES_AT/HOSTS edges open for that reason. What is buildable now
is the *ingestion* half: an operator (or a future discovery job) can
DECLARE the topology — DNS → CDN → WAF → load balancer → system — and
the graph, exposure queries, and entry-candidate detection immediately
honor it, with every node and edge honestly labeled ``source:
"declared"`` so nobody mistakes it for a scanned surface.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped

#: node kinds the ingest API accepts (report 58 §2 named the first six)
NODE_KINDS = {
    "dns": "DNSRecord",
    "cdn": "CDN",
    "waf": "WAF",
    "load_balancer": "LoadBalancer",
    "k8s_service": "K8sService",
    "pod": "Pod",
    "ip_range": "IpRange",
    "service": "NetworkService",
}

#: edge relations between topology nodes
EDGE_RELATIONS = {"RESOLVES_TO", "PROXIES_TO", "ROUTES_TO", "PEERS_WITH"}

#: what a node's declared system links mean (TERMINATES_AT/HOSTS per 58)
NODE_SYSTEM_RELATIONS = {"TERMINATES_AT", "HOSTS"}


class TopologyNode(BaseModel, TenantScoped):
    __tablename__ = "topology_nodes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_topology_node_name"),
        Index("ix_topology_nodes_kind", "kind"),
    )

    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    #: operator notes / addresses / listeners — free-form, provenance kept
    attrs: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    #: systems this node frontends (TERMINATES_AT) or hosts (HOSTS)
    system_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    system_relation: Mapped[str] = mapped_column(String(20), nullable=False,
                                                 default="TERMINATES_AT")
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="declared")


class TopologyEdge(BaseModel, TenantScoped):
    __tablename__ = "topology_edges"
    __table_args__ = (
        UniqueConstraint("tenant_id", "from_name", "to_name", "relation",
                         name="uq_topology_edge"),
        Index("ix_topology_edges_from", "from_name"),
    )

    from_name: Mapped[str] = mapped_column(String(300), nullable=False)
    to_name: Mapped[str] = mapped_column(String(300), nullable=False)
    relation: Mapped[str] = mapped_column(String(40), nullable=False)
    attrs: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="declared")
