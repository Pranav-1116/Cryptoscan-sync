"""PQC migration intelligence: waves, blockers, interoperability, verified progress.

This register is the persisted plan state behind the PQC Migration Intelligence
workspace. The quantum-vulnerable inventory itself is projected from live estate
reads (TechBOM/CBOM) elsewhere; what these tables own is the migration plan:
which waves exist, what blocks them, which peers interoperate, and which
progress claims have been verified against evidence.

Honesty boundary: a progress row is a claim until the verification endpoint
writes a verdict, and that verdict requires an evidence reference. Nothing in
this module promotes a claim to verified on its own, and an ``accepted`` blocker
is a recorded governance decision — never a silent close.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel, utcnow

WAVE_STATES: tuple[str, ...] = (
    "planned",
    "active",
    "verified",
    "blocked",
    "superseded",
)
BLOCKER_STATES: tuple[str, ...] = ("open", "cleared", "accepted")
PROGRESS_VERIFICATION_STATES: tuple[str, ...] = (
    "recorded",
    "verified",
    "refuted",
    "stale",
)


class PqcMigrationWave(BaseModel):
    """One migration wave of the PQC plan."""

    __tablename__ = "pqc_migration_waves"
    __table_args__ = (
        Index("ix_pqc_wave_status_planned", "status", "planned_window"),
    )

    wave_key: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    scope_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    planned_window: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="planned")
    status_note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


class PqcMigrationBlocker(BaseModel):
    """Something blocking a wave: raised explicitly, resolved explicitly."""

    __tablename__ = "pqc_migration_blockers"
    __table_args__ = (
        Index("ix_pqc_blocker_wave_state", "wave_id", "state"),
    )

    wave_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("pqc_migration_waves.id"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    raised_by: Mapped[str] = mapped_column(String(200), nullable=False)
    raised_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    resolved_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolution_note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


class PqcInteropNote(BaseModel):
    """An interoperability observation against a peer system for one wave."""

    __tablename__ = "pqc_interop_notes"
    __table_args__ = (
        Index("ix_pqc_interop_wave_peer", "wave_id", "peer_system"),
    )

    wave_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("pqc_migration_waves.id"), nullable=False, index=True
    )
    peer_system: Mapped[str] = mapped_column(String(200), nullable=False)
    protocol: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recorded_by: Mapped[str] = mapped_column(String(200), nullable=False)


class PqcProgressRecord(BaseModel):
    """A progress claim on a wave, and (optionally) its verification verdict."""

    __tablename__ = "pqc_progress_records"
    __table_args__ = (
        Index("ix_pqc_progress_wave_verif", "wave_id", "verification_status"),
    )

    wave_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("pqc_migration_waves.id"), nullable=False, index=True
    )
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recorded_by: Mapped[str] = mapped_column(String(200), nullable=False)
    verification_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="recorded"
    )
    verified_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verification_note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
