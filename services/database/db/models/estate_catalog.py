"""The durable canonical estate catalogue (spec 94 §19, §22 "canonical estate model").

Until now the twin was *reconstructed*: the newest stored discovery payload was read
back and a graph was rebuilt from it. That is enough to answer questions about "now",
and it is not enough to answer the questions a twin exists for — when did this asset
first appear, when was it last seen, is it retired or merely unobserved, and which
evidence is behind this edge. Those need records with a life longer than one run.

Three tables, one rule: **the catalogue is derived from evidence, never edited by
hand.** Each row is materialised from a graph by :mod:`api.estate_catalog`, carries
the evidence ids behind it, and moves through a small lifecycle:

    ACTIVE   observed in the most recent observation
    STALE    observed before, absent from the latest observation — NOT deleted

``STALE`` is the important one. A host that stopped answering, a plane that failed and
a decommissioned server all look identical in a diff; the catalogue keeps the row,
records ``last_seen_at``, and refuses to let absence become deletion. Nothing here is
ever removed automatically — an auditor asking "when did we stop seeing HSM-03?" gets
an answer.

``observation_count`` on each row is why a change feed can be trusted: an asset seen
in 40 of 41 runs is a different thing from one seen once, and the difference is not
visible in any single snapshot.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EstateAssetRecord(BaseModel, TenantScoped):
    """One canonical asset, with its lifecycle across observations."""

    __tablename__ = "estate_assets"
    __table_args__ = (
        Index("ix_estate_assets_tenant_asset", "tenant_id", "asset_id", unique=True),
        Index("ix_estate_assets_type_env", "asset_type", "environment"),
    )

    #: the graph's stable id — identity, not a row number
    asset_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(400), nullable=False)
    environment: Mapped[Optional[str]] = mapped_column(String(120), index=True)
    owner: Mapped[Optional[str]] = mapped_column(String(200), index=True)
    location: Mapped[Optional[str]] = mapped_column(String(200))
    source: Mapped[Optional[str]] = mapped_column(String(200))
    identity: Mapped[Optional[dict]] = mapped_column(JSON)
    attributes: Mapped[Optional[dict]] = mapped_column(JSON)
    evidence_ids: Mapped[Optional[list]] = mapped_column(JSON)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    lifecycle_state: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_run_id: Mapped[Optional[str]] = mapped_column(String(64))
    last_run_id: Mapped[Optional[str]] = mapped_column(String(64))


class EstateRelationshipRecord(BaseModel, TenantScoped):
    """One edge, with the basis and evidence that established it — or why it did not.

    ``status`` is ``ESTABLISHED`` or ``UNRESOLVED``. Unresolved candidates are stored
    rather than dropped (they are what a bank most wants to chase), and they are never
    counted as relationships: every read path filters on status.
    """

    __tablename__ = "estate_relationships"
    __table_args__ = (
        Index("ix_estate_relationships_tenant_rel", "tenant_id", "relationship_id", unique=True),
        Index("ix_estate_relationships_subject", "subject_id"),
        Index("ix_estate_relationships_object", "object_id"),
    )

    relationship_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(120), nullable=False)
    subject_name: Mapped[Optional[str]] = mapped_column(String(400))
    predicate: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    object_id: Mapped[str] = mapped_column(String(120), nullable=False)
    object_name: Mapped[Optional[str]] = mapped_column(String(400))
    basis: Mapped[Optional[str]] = mapped_column(String(80))
    confidence: Mapped[Optional[str]] = mapped_column(String(20))
    #: §8 — what kind of evidence established the edge, and when it was observed. A
    #: relationship is not a foreign key: an operator asking "how do you know?" needs the
    #: answer on the record, not only in the evidence table it points at
    evidence_type: Mapped[Optional[str]] = mapped_column(String(40))
    observed_at: Mapped[Optional[str]] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ESTABLISHED", index=True)
    reason: Mapped[Optional[str]] = mapped_column(Text)
    evidence_ids: Mapped[Optional[list]] = mapped_column(JSON)
    attributes: Mapped[Optional[dict]] = mapped_column(JSON)

    lifecycle_state: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class EstateCryptoRecord(BaseModel, TenantScoped):
    """One cryptographic artefact as evidenced, with the plane it was observed on.

    Keyed by the graph's ``artifact_id``, so the same algorithm observed on the
    capability plane and on the runtime plane are **two rows**, never one merged
    claim. That separation is the whole reason this product exists: "the library
    supports AES-128" and "the API used AES-256-GCM" are both true and must stay
    distinguishable after they are stored.
    """

    __tablename__ = "estate_crypto_assets"
    __table_args__ = (
        Index("ix_estate_crypto_tenant_artifact", "tenant_id", "artifact_id", unique=True),
        Index("ix_estate_crypto_algorithm", "algorithm"),
        Index("ix_estate_crypto_state", "usage_state"),
    )

    artifact_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    asset_name: Mapped[Optional[str]] = mapped_column(String(400))
    asset_type: Mapped[Optional[str]] = mapped_column(String(40), index=True)

    algorithm: Mapped[Optional[str]] = mapped_column(String(120), index=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(60), index=True)
    curve: Mapped[Optional[str]] = mapped_column(String(80))
    key_size: Mapped[Optional[int]] = mapped_column(Integer)
    mode: Mapped[Optional[str]] = mapped_column(String(60))
    role: Mapped[Optional[str]] = mapped_column(String(60))
    layer: Mapped[Optional[str]] = mapped_column(String(40), index=True)

    #: SUPPORTED / CONFIGURED / NEGOTIATED / OBSERVED — the capability≠use axis
    usage_state: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    evidence_type: Mapped[Optional[str]] = mapped_column(String(40))
    confidence: Mapped[Optional[str]] = mapped_column(String(20))
    evidence_ids: Mapped[Optional[list]] = mapped_column(JSON)
    source: Mapped[Optional[str]] = mapped_column(String(200))

    lifecycle_state: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class EstateEvidenceRecord(BaseModel, TenantScoped):
    """One evidence record, kept after the run that produced it (spec 94 §11, §19).

    Evidence used to live only inside the stored discovery payload, which made a
    provenance question ("who observed this, from where, when, with what hash") an
    exercise in finding the right run. The record is content-addressed, so the same
    fact observed twice is one row whose ``observation_count`` advances — not two
    rows that make a steady estate look busy.
    """

    __tablename__ = "estate_evidence"
    __table_args__ = (
        Index("ix_estate_evidence_tenant_evidence", "tenant_id", "evidence_id", unique=True),
        Index("ix_estate_evidence_target", "target_id"),
    )

    evidence_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    schema_version: Mapped[Optional[str]] = mapped_column(String(80))
    source: Mapped[Optional[str]] = mapped_column(String(400))
    collector: Mapped[Optional[str]] = mapped_column(String(400), index=True)
    evidence_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(20))
    target_id: Mapped[str] = mapped_column(String(120), nullable=False)
    layer: Mapped[Optional[str]] = mapped_column(String(40), index=True)
    facts: Mapped[Optional[dict]] = mapped_column(JSON)
    observed_at: Mapped[Optional[str]] = mapped_column(String(64))

    #: ACTIVE while the collector still produces it, STALE once it stops
    lifecycle_state: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class EstateObservationRecord(BaseModel, TenantScoped):
    """One fact *value*, with the window in which it was the observed truth (§19).

    This is the table the twin was missing: ``observation_count`` on an asset says how
    often the asset was seen, and cannot answer "what was its version on Tuesday".
    Each row is one ``(asset, fact_type, value)`` triple, so a value that changes adds a
    row and retires the previous one to ``HISTORICAL`` instead of overwriting it.

    ``CURRENT`` / ``HISTORICAL`` is about *this fact*, not about the estate: a fact that
    is no longer observed is history, and a fact still observed holds its current value
    however many times it has moved.
    """

    __tablename__ = "estate_observations"
    __table_args__ = (
        Index("ix_estate_observations_tenant_obs", "tenant_id", "observation_id", unique=True),
        Index("ix_estate_observations_asset_fact", "asset_id", "fact_type"),
    )

    observation_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    fact_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    value: Mapped[Optional[str]] = mapped_column(Text)
    value_kind: Mapped[Optional[str]] = mapped_column(String(40))
    evidence_id: Mapped[Optional[str]] = mapped_column(String(80), index=True)
    evidence_type: Mapped[Optional[str]] = mapped_column(String(40))
    layer: Mapped[Optional[str]] = mapped_column(String(40))

    lifecycle_state: Mapped[str] = mapped_column(String(20), nullable=False, default="CURRENT", index=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
