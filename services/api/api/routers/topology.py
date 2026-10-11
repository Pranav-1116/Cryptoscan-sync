"""Declared network topology API (advanced/58 P0#1–2, round 31).

- ``POST /network/topology`` — declare the topology (full replace,
  validated whole before anything is persisted; a rejection leaves the
  stored topology untouched).
- ``GET  /network/topology`` — the stored declaration.
- ``GET  /network/topology/paths?system_id=`` — the declared chains
  (dns/cdn/waf/lb → …) that front one system.

Everything is labeled ``source: "declared"`` — the platform still does
not scan network topology; this is the ingestion surface a live
cloud/K8s discovery job can write into later, unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_admin
from db.repositories.topology_repository import TopologyRepository
from db.topology import TopologyError, declared_chains_to_system, validate_topology_document

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network/topology", tags=["topology"])


class TopologyDocument(BaseModel):
    document: dict[str, Any]


@router.post("")
def declare_topology(
    body: TopologyDocument,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    try:
        normalized = validate_topology_document(body.document)
    except TopologyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    repo = TopologyRepository(db)
    counts = repo.replace_all(normalized)
    db.commit()
    logger.info("topology_declared", extra={**counts, "actor": admin})
    return {"accepted": True, **counts,
            "source": "declared",
            "note": "full replace; the document is the declared topology"}


@router.get("")
def get_topology(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = TopologyRepository(db)
    payload = repo.graph_payload()
    return {
        "format": "zelnx-topology/v1",
        "source": "declared",
        "nodes": [
            {"name": n["name"], "kind": n["kind"], "attrs": n["attrs"],
             "system_ids": n["system_ids"], "system_relation": n["system_relation"],
             "source": n["source"]}
            for n in payload["nodes"]
        ],
        "edges": payload["edges"],
    }


@router.get("/paths")
def topology_paths(
    system_id: str = Query(..., min_length=1),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = TopologyRepository(db)
    payload = repo.graph_payload()
    chains = declared_chains_to_system(payload["nodes"], payload["edges"], system_id)
    return {
        "system_id": system_id,
        "chains": [
            [
                {"name": step["node"]["name"], "kind": step["node"]["kind"],
                 "relation": step["relation"]}
                for step in chain
            ]
            for chain in chains
        ],
        "chain_count": len(chains),
        "source": "declared",
        "note": "declared chains only — the platform does not scan topology",
    }
