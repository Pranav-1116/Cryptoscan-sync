"""In-memory Elasticsearch test double over the query shapes the adapter sends.

It does not parse the query DSL and cannot qualify a real Elasticsearch
deployment. It understands exactly the bool/filter/multi_match/must_not
shapes ``ElasticDependencySearch`` builds, and enforces the store's
tenant-isolation
contract from the other side: every query body must carry a ``term`` filter
on ``tenant_id``. A query without one raises — isolation is enforced by the
query layer, never assumed from index layout.
"""

from __future__ import annotations

from typing import Any


class TenantIsolationError(RuntimeError):
    """A query reached the store without a tenant filter."""


def _tenant_of(body: dict[str, Any]) -> str:
    bool_ = (body.get("query") or {}).get("bool") or {}
    for clause in bool_.get("filter") or []:
        term = clause.get("term") or {}
        if "tenant_id" in term:
            return str(term["tenant_id"])
    raise TenantIsolationError("dependency search query lacks a tenant filter")


def _terms(body: dict[str, Any]) -> dict[str, str]:
    bool_ = (body.get("query") or {}).get("bool") or {}
    out = {}
    for clause in bool_.get("filter") or []:
        term = clause.get("term") or {}
        out.update({key: str(value) for key, value in term.items()})
    return out


def _multi_match_text(body: dict[str, Any]) -> str:
    bool_ = (body.get("query") or {}).get("bool") or {}
    for clause in bool_.get("must") or []:
        multi = clause.get("multi_match") or {}
        if "query" in multi:
            return str(multi["query"]).lower()
        match = clause.get("match") or {}
        for value in match.values():
            return str(value).lower()
    return ""


def _match_object(body: dict[str, Any]) -> str | None:
    bool_ = (body.get("query") or {}).get("bool") or {}
    for clause in list(bool_.get("must") or []) + list(bool_.get("filter") or []):
        match = clause.get("match") or {}
        if "object_id" in match:
            return str(match["object_id"]).lower()
    return None


class _Indices:
    def __init__(self) -> None:
        self.mappings: dict[str, dict[str, Any]] = {}

    def exists(self, index: str) -> bool:
        return index in self.mappings

    def create(self, index: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        self.mappings[index] = body or {}
        return {"acknowledged": True}


class FakeElasticClient:
    def __init__(self) -> None:
        self.indices = _Indices()
        self.docs: dict[str, dict[str, Any]] = {}
        self.bodies: list[dict[str, Any]] = []

    def ping(self) -> bool:
        return True

    def index(self, index: str, id: str, document: dict[str, Any]) -> dict[str, Any]:
        self.docs[id] = document
        return {"result": "created", "_id": id}

    def _matches(self, body: dict[str, Any], doc: dict[str, Any]) -> bool:
        terms = _terms(body)
        for key, value in terms.items():
            if str(doc.get(key)) != value:
                return False
        bool_ = (body.get("query") or {}).get("bool") or {}
        for clause in bool_.get("must_not") or []:
            term = clause.get("term") or {}
            for key, value in term.items():
                if str(doc.get(key)) == str(value):
                    return False
        text = _multi_match_text(body)
        if text and not any(
            text in str(doc.get(field) or "").lower()
            for field in ("name", "labels", "evidence", "relation", "subject_id", "object_id")
        ):
            return False
        wanted = _match_object(body)
        if wanted is not None and wanted not in str(doc.get("object_id") or "").lower():
            return False
        return True

    def get(self, index: str, id: str) -> dict[str, Any]:
        if id not in self.docs:
            raise KeyError(id)
        return {"_id": id, "_source": self.docs[id]}

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        tenant = _tenant_of(body)
        size = int(body.get("size") or 10)
        hits = [
            {"_id": id_, "_score": 1.0, "_source": doc}
            for id_, doc in self.docs.items()
            if doc.get("tenant_id") == tenant and self._matches(body, doc)
        ]
        return {"hits": {"hits": hits[:size], "total": {"value": len(hits)}}}

    def delete_by_query(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        tenant = _tenant_of(body)
        doomed = [id_ for id_, doc in self.docs.items()
                  if doc.get("tenant_id") == tenant and self._matches(body, doc)]
        for id_ in doomed:
            del self.docs[id_]
        return {"deleted": len(doomed)}

    def count(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        tenant = _tenant_of(body)
        n = sum(1 for doc in self.docs.values()
                if doc.get("tenant_id") == tenant and self._matches(body, doc))
        return {"count": n}
