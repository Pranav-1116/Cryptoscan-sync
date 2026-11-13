"""Deployment-control attestations and the data-custody map.

:mod:`shared_models.deployment_controls` decides what an attestation means (a
backup is not a tested restore; a stale drill cannot hold readiness). These
tables store the attestations and the custody map it reads:

* :class:`DeploymentAttestation` — one drill/attestation of one control, with
  the evidence ids behind it. A failed drill files ``status="FAILED"`` and stays
  visible; there is no delete path;
* :class:`DeploymentCustodyEntry` — where one custody class lives and who
  controls it. "The bank keeps control" is a located, named row or it is not
  control.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


# platform-scope: product deployment-control evidence plane — one
# drill/attestation of one control with its evidence ids (a failed drill
# files FAILED and stays visible), not tenant inventory.
class DeploymentAttestation(BaseModel):
    __tablename__ = "deployment_attestations"
    __table_args__ = (
        Index("ix_deployment_attestation_control_observed", "control", "observed_at"),
    )

    control: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="OK")
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                  nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


# platform-scope: product deployment-control evidence plane — the
# data-custody map (which custody class lives where, who controls it);
# deployment-level rows, not tenant inventory.
class DeploymentCustodyEntry(BaseModel):
    __tablename__ = "deployment_custody_entries"

    #: database | evidence | crypto_metadata
    custody_class: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    controller: Mapped[str] = mapped_column(String(120), nullable=False)
    location: Mapped[str] = mapped_column(String(255), nullable=False)
