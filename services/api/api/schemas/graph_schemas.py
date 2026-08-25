"""Graph visualization schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GraphVis(BaseModel):
    nodes: list[dict] = Field(default_factory=list)
    edges: list[dict] = Field(default_factory=list)
    backend: str = "memory"
