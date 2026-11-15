"""Dependency search in Elasticsearch: find nodes, edges, dependents by text.

PostgreSQL is the authoritative record of every relationship. This store is a
rebuildable projection — searchable copies of node/edge text (names,
predicates, lifecycle state, evidence detail), never authoritative asset or
relationship rows.

Tenant isolation is enforced by the query layer and authorization, never
assumed from index layout: every query carries a ``term`` filter on
``tenant_id``, and the test double rejects any query without one.
"""

from __future__ import annotations

import logging
from typing import Any

from shared_models.dependency_semantics import edge_relation, system_id
from shared_models.relationship_lifecycle import FIELDS as LIFECYCLE_FIELDS

logger = logging.getLogger(__name__)

INDEX_NAME = "cryptoscan-dependency-graph"

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "tenant_id": {"type": "keyword"},
            "kind": {"type": "keyword"},
            "identity": {"type": "keyword"},
            "name": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
            "subject_id": {"type": "keyword"},
            "object_id": {"type": "keyword"},
            "relation": {"type": "keyword"},
            "labels": {"type": "text"},
            "environment": {"type": "keyword"},
            "criticality": {"type": "keyword"},
            "owner": {"type": "keyword"},
            "lifecycle_state": {"type": "keyword"},
            "lifecycle_revision": {"type": "keyword"},
            "lifecycle_source": {"type": "keyword"},
            "lifecycle_reason": {"type": "text"},
            "lifecycle_evidence_ref": {"type": "keyword"},
            "evidence": {"type": "text"},
        }
    }
}

SEARCH_FIELDS = ("name^3", "labels", "evidence", "relation", "subject_id", "object_id")


def _tenant_filter(tenant_id: str) -> dict[str, Any]:
    """The single choke point every query passes through."""
    return {"term": {"tenant_id": tenant_id}}


def _require_tenant(tenant_id: str) -> str:
    tenant = (tenant_id or "").strip()
    if not tenant:
        raise ValueError("dependency search requires a tenant")
    return tenant


def doc_id(tenant_id: str, kind: str, identity: str) -> str:
    return f"{tenant_id}::{kind}::{identity}"


def doc_from_system(tenant_id: str, system: dict[str, Any]) -> dict[str, Any]:
    sid = system_id(system.get("system_id") or system.get("id"))
    return {
        "tenant_id": tenant_id,
        "kind": "system",
        "identity": sid,
        "name": str(system.get("name") or sid),
        "labels": " ".join(str(x) for x in system.get("compliance_scopes") or []),
        "environment": system.get("environment"),
        "criticality": system.get("criticality"),
        "owner": system.get("owner"),
        "evidence": str(system.get("evidence") or ""),
    }


def doc_from_asset(tenant_id: str, asset: dict[str, Any]) -> dict[str, Any]:
    aid = str(asset.get("asset_id") or asset.get("id") or "")
    return {
        "tenant_id": tenant_id,
        "kind": "asset",
        "identity": aid,
        "name": " ".join(str(x) for x in (aid, asset.get("algorithm"), asset.get("purpose")) if x),
        "labels": str(asset.get("file_path") or ""),
        "subject_id": system_id(asset.get("system_id")),
        "evidence": str(asset.get("evidence") or ""),
    }


def doc_from_edge(tenant_id: str, edge: dict[str, Any]) -> dict[str, Any]:
    subject = system_id(edge.get("subject") or edge.get("from") or edge.get("parent_id"))
    object_ = system_id(edge.get("object") or edge.get("to") or edge.get("child_id"))
    if not subject or not object_:
        raise ValueError("edge document requires subject and object")
    relation = edge_relation(edge)
    doc = {
        "tenant_id": tenant_id,
        "kind": "edge",
        "identity": f"{subject}::{relation}::{object_}",
        "name": f"{subject} {relation} {object_}",
        "subject_id": subject,
        "object_id": object_,
        "relation": relation,
        "evidence": str(edge.get("detail") or edge.get("evidence") or ""),
    }
    for field in LIFECYCLE_FIELDS:
        if field != "record_id" and edge.get(field) is not None:
            doc[field] = edge.get(field)
    return doc


class ElasticDependencySearch:
    """Tenant-bound dependency search. Every query carries the tenant filter."""

    backend = "elasticsearch"

    def __init__(self, client: Any, index: str = INDEX_NAME) -> None:
        self.client = client
        self.index = index

    def apply_schema(self) -> dict[str, Any]:
        if not self.client.indices.exists(index=self.index):
            self.client.indices.create(index=self.index, body=INDEX_MAPPING)
            return {"created": self.index}
        return {"created": None}

    def _index_doc(self, tenant_id: str, kind: str, identity: str, doc: dict[str, Any]) -> str:
        if not identity:
            raise ValueError("projection document requires an identity")
        doc_id_ = doc_id(tenant_id, kind, identity)
        self.client.index(index=self.index, id=doc_id_, document=doc)
        return doc_id_

    def index_system(self, tenant_id: str, system: dict[str, Any]) -> str:
        tenant = _require_tenant(tenant_id)
        doc = doc_from_system(tenant, system)
        return self._index_doc(tenant, "system", doc["identity"], doc)

    def index_asset(self, tenant_id: str, asset: dict[str, Any]) -> str:
        tenant = _require_tenant(tenant_id)
        doc = doc_from_asset(tenant, asset)
        return self._index_doc(tenant, "asset", doc["identity"], doc)

    def index_edge(self, tenant_id: str, edge: dict[str, Any]) -> str:
        tenant = _require_tenant(tenant_id)
        doc = doc_from_edge(tenant, edge)
        return self._index_doc(tenant, "edge", doc["identity"], doc)

    def index_payload(self, tenant_id: str, payload: dict[str, Any]) -> dict[str, int]:
        """Project the authoritative payload (systems/assets/edges) into the index."""
        tenant = _require_tenant(tenant_id)
        counts = {"systems": 0, "assets": 0, "edges": 0}
        for system in payload.get("systems") or []:
            self.index_system(tenant, system)
            counts["systems"] += 1
        for asset in payload.get("assets") or []:
            self.index_asset(tenant, asset)
            counts["assets"] += 1
        for edge in payload.get("edges") or []:
            self.index_edge(tenant, edge)
            counts["edges"] += 1
        return counts

    def _search_body(
        self,
        tenant_id: str,
        text: str = "",
        *,
        kind: str | None = None,
        extra_filter: list[dict[str, Any]] | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        filters = [_tenant_filter(tenant_id)]
        if kind:
            filters.append({"term": {"kind": kind}})
        filters.extend(extra_filter or [])
        body: dict[str, Any] = {
            "query": {
                "bool": {
                    "filter": filters,
                }
            },
            "size": max(1, min(int(limit), 100)),
        }
        if text:
            body["query"]["bool"]["must"] = [
                {"multi_match": {"query": text, "fields": list(SEARCH_FIELDS)}}
            ]
        return body

    def search(
        self, tenant_id: str, text: str = "", *, kind: str | None = None, limit: int = 20
    ) -> dict[str, Any]:
        tenant = _require_tenant(tenant_id)
        body = self._search_body(tenant, text, kind=kind, limit=limit)
        response = self.client.search(index=self.index, body=body)
        hits = response.get("hits") or {}
        rows = [
            {"id": hit.get("_id"), "score": hit.get("_score"), **(hit.get("_source") or {})}
            for hit in hits.get("hits") or []
        ]
        total = (hits.get("total") or {}).get("value", len(rows))
        return {"hits": rows, "total": total, "backend": self.backend, "query": text}

    def dependents_of(self, tenant_id: str, name: str, *, limit: int = 20) -> dict[str, Any]:
        """Edges whose object side matches ``name`` — who depends on this."""
        tenant = _require_tenant(tenant_id)
        body = self._search_body(
            tenant, name, kind="edge",
            extra_filter=[{"match": {"object_id": name}}],
            limit=limit,
        )
        response = self.client.search(index=self.index, body=body)
        hits = response.get("hits") or {}
        rows = [hit.get("_source") or {} for hit in hits.get("hits") or []]
        return {"edges": rows, "total": (hits.get("total") or {}).get("value", len(rows)),
                "backend": self.backend}

    def purge_tenant(self, tenant_id: str) -> int:
        """Drop the tenant's projection rows — rebuild-from-PostgreSQL support."""
        tenant = _require_tenant(tenant_id)
        body = {"query": {"bool": {"filter": [_tenant_filter(tenant)]}}}
        response = self.client.delete_by_query(index=self.index, body=body)
        return int(response.get("deleted") or 0)

    def count(self, tenant_id: str) -> int:
        tenant = _require_tenant(tenant_id)
        body = {"query": {"bool": {"filter": [_tenant_filter(tenant)]}}}
        response = self.client.count(index=self.index, body=body)
        return int(response.get("count") or 0)
