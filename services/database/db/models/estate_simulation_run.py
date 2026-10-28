"""Persisted Digital Twin simulation runs, quarantined (spec 94 §17, §19).

Spec 94 §19 asks for a ``simulation_runs`` table. This is it, with the one property
that makes storing a hypothetical safe: **every row is quarantined**. It stores the
*answer* the engine produced (scenario, base projection id, impact, blockers, BOM
diff) and never any estate facts, so nothing here can be merged back into an
``EstateGraph``, a snapshot, a drift comparison or a BOM projection.

Three columns carry the honesty:

* ``live_state_modified`` — asserted False at write time; a stored simulation is
  always one that left the estate alone;
* ``base_projection_id`` — the evidence state the answer describes. Once the live
  twin differs, the row is *superseded*, and the API says so rather than presenting
  a stale impact figure as current;
* ``observations`` — re-running the same question against the same evidence
  increments this instead of creating a second "result" that resembles a change.

Rows are immutable apart from the observation counter and the last-run timestamp: a
simulation is a record of what was computed, not a document to be edited.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, Text, true
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EstateSimulationRun(BaseModel, TenantScoped):
    """One simulated scenario, computed against one evidence state."""

    __tablename__ = "estate_simulation_runs"
    __table_args__ = (
        Index("ix_estate_simulation_runs_tenant_sim", "tenant_id", "simulation_id", unique=True),
        Index("ix_estate_simulation_runs_base_projection", "base_projection_id"),
    )

    #: the tenant_id column and its ORM guard come from TenantScoped — a stored
    #: simulation belongs to one estate, and a query that forgets the scope is a
    #: bug the mixin catches rather than a cross-estate read

    #: content-addressed: base projection id + scenario
    simulation_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    scenario: Mapped[Optional[dict]] = mapped_column(JSON)

    base_snapshot_id: Mapped[Optional[str]] = mapped_column(String(96))
    base_projection_id: Mapped[Optional[str]] = mapped_column(String(64))
    simulated_projection_id: Mapped[Optional[str]] = mapped_column(String(64))

    matched_evidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    affected_assets: Mapped[Optional[list]] = mapped_column(JSON)
    impact: Mapped[Optional[dict]] = mapped_column(JSON)
    bom_diff: Mapped[Optional[dict]] = mapped_column(JSON)
    blockers: Mapped[Optional[list]] = mapped_column(JSON)

    #: always False in a stored row; a simulation that modified the live graph is refused
    live_state_modified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")

    #: the quarantine, stated in the data rather than only in the API layer
    quarantined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    is_estate_state: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")

    observations: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    created_by: Mapped[Optional[str]] = mapped_column(String(160))
    label: Mapped[Optional[str]] = mapped_column(Text)
