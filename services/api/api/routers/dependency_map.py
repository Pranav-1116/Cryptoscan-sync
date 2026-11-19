"""Crypto dependency map + selectable system cascade (Twin & dependencies)."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.crypto_dependency_map import build_dependency_map, simulate_cascade
from api.dependencies import get_current_user, get_db_session

router = APIRouter(tags=["graph"])


class DependencyMapResponse(BaseModel):
    """Top-level contract of the dependency map; node and edge rows pass through."""
    model_config = ConfigDict(extra="allow")
    policy: dict[str, Any]
    generated_at: str
    systems: list[dict[str, Any]]
    components: list[dict[str, Any]]
    libraries: list[dict[str, Any]]
    algorithms: list[dict[str, Any]]
    edges: dict[str, list[dict[str, Any]]]
    coverage: dict[str, Any]


class CascadeResponse(BaseModel):
    """Top-level contract of a cascade run; system rows pass through."""
    model_config = ConfigDict(extra="allow")
    direction: str
    hops: int
    seeds: list[dict[str, Any]]
    algorithm_seeds: list[dict[str, Any]]
    impacted: list[dict[str, Any]]
    unknown_selections: Any = None
    summary: dict[str, Any]


@router.get("/graph/dependency-map", response_model=DependencyMapResponse)
def get_dependency_map(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """System → component → library → algorithm, plus system → system
    dependencies. Every edge names the stored record that establishes it."""
    return build_dependency_map(db)


class CascadeRequest(BaseModel):
    system_ids: list[str] = Field(default_factory=list, max_length=500)
    algorithm_ids: list[str] = Field(default_factory=list, max_length=200)
    direction: Literal["dependents", "providers", "both"] = "dependents"
    hops: int = Field(default=6, ge=1, le=12)


@router.post("/graph/dependency-map/cascade", response_model=CascadeResponse)
def post_dependency_cascade(body: CascadeRequest, user: str = Depends(get_current_user),
                            db: Session = Depends(get_db_session)):
    """Cascade from the selected systems and/or algorithms over ACTIVE
    propagating dependency edges, with a witness path per reached system."""
    if not body.system_ids and not body.algorithm_ids:
        raise HTTPException(status_code=400, detail="select at least one system or algorithm")
    return simulate_cascade(build_dependency_map(db), system_ids=body.system_ids,
                            algorithm_ids=body.algorithm_ids, direction=body.direction, hops=body.hops)
