"""Reachability / blast-radius schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BlastRadius(BaseModel):
    start: str | None = None
    systems: list[dict] = Field(default_factory=list)
    hops: int = 5
    nodes_visited: int = 0
    backend: str = "memory"
