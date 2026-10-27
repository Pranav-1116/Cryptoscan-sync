"""Crypto threat-intelligence advisories (deep/30, round 31).

deep/30's verdict was "roadmap, not remediation" — no STIX/TAXII, no
ATT&CK, no feed integration. The buildable slice of that roadmap is
the platform-native half: ALGORITHM advisories (deprecations, attack
cost updates, key-size minimums, implementation warnings) arriving as
signed bundles — exactly the air-gap feed convention the platform
already uses for vulnerability feeds — and an annotation-only surface
that tells an asset's risk view which advisories name its algorithm.

Annotation-never-rewrite (the standing convention since the
corroboration work): an advisory never changes a stored score; it is
reported beside it, with its own provenance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped

ADVISORY_TYPES = {
    "DEPRECATION",       # authority withdraws the algorithm
    "RESTRICTION",       # scoped restriction (e.g. new-hope only after date D)
    "ATTACK_UPDATE",     # cryptanalytic result: attack cost estimate changed
    "KEY_SIZE_MINIMUM",  # authority raised the acceptable parameter floor
    "IMPLEMENTATION",    # specific library/device implementation flaw
    "DISCLOSURE",        # generic disclosure naming the algorithm
}

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class AlgorithmAdvisory(BaseModel, TenantScoped):
    __tablename__ = "algorithm_advisories"
    __table_args__ = (
        UniqueConstraint("source", "advisory_id", name="uq_advisory_source_id"),
        Index("ix_advisories_algorithm", "algorithm"),
        Index("ix_advisories_effective", "effective_date"),
    )

    advisory_id: Mapped[str] = mapped_column(String(120), nullable=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    advisory_type: Mapped[str] = mapped_column(String(30), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    title: Mapped[Optional[str]] = mapped_column(String(400), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(600), nullable=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    effective_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    #: machine-readable payload (e.g. {"attack_cost_bits": 134}) — kept raw,
    #: surfaced as annotation, never folded into scores silently
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
