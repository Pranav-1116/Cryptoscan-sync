"""Immutable, content-addressed Technology BOM snapshot (deterministic).

The spec: every exported BOM must have a stable snapshot identity so the customer
knows *exactly which environment state* it represents (spec #14). This mirrors
:class:`GraphSnapshot` — a snapshot is recorded only when the canonicalized BOM
component set changed (same fingerprint -> same version, no duplicates), and the
snapshot carries the full materialized layers so it is self-contained and can be
compared or exported at any time.
"""

from __future__ import annotations

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class TechnologyBomSnapshot(BaseModel, TenantScoped):
    __tablename__ = "technology_bom_snapshots"

    #: monotonic version number (1..n), unique per snapshot.
    version: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    #: sha256 over the canonicalized BOM component set.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: human-readable immutable snapshot id (TECHBOM-YYYYMMDD-HHMMSS).
    snapshot_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(100), nullable=False, default="default")

    total_components: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: per-layer counts (sbom / cbom / hbom / vendor / certificates).
    components_by_layer: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    #: the materialized, self-contained layers (JSON).
    state: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    #: diff vs the previous snapshot (per-layer added/removed bom-refs).
    diff: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "parent_fingerprint": self.parent_fingerprint,
            "snapshot_id": self.snapshot_id,
            "environment": self.environment,
            "total_components": self.total_components,
            "components_by_layer": self.components_by_layer or {},
            "state": self.state or {},
            "diff": self.diff or {},
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
