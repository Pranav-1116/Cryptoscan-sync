"""Content-addressed storage objects — evidence bytes stored once.

The storage-optimization core (spec 2.1/7). Every piece of retained
content — raw collector output, evidence bundles, snapshot deltas, scan
manifests — is identified by the SHA-256 of its **plaintext** bytes and
stored exactly once per tenant:

* ``content_objects`` is the **metadata** (searchable: kind, sizes, codec,
  tier, category, references). The large bytes live elsewhere — in
  ``content_object_bodies`` (database backend) or in bank-approved object
  storage (file backend) — metadata separation, so listing and searching
  the evidence estate never drags megabytes through the database.
* ``(tenant_id, sha256)`` is unique: the same bytes submitted on Monday,
  Tuesday and Wednesday occupy one object. The tenant is part of the
  identity on purpose — deduplication never becomes a cross-tenant side
  channel ("which other bank has these bytes?" must be unanswerable).
* Deduplication stops at the bytes. Provenance (who collected what, when,
  from where, under whose authorization) is NEVER deduplicated: every
  collection event gets its own ``evidence_content_links`` row even when
  the content hash is identical (see db/storage/provenance.py).
* ``ref_count`` counts referencing rows (evidence links, deltas, jobs).
  A body is droppable at 0 and only at 0 — the GC checks the count, never
  guesses.
* ``storage_tier`` (hot → warm → cold) drives object lifecycle: older
  approved content migrates to cheaper storage, never to deletion without
  policy saying so.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import BigInteger, DateTime, Index, Integer, JSON, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantOwned

#: Object kinds stored through the content-addressed store.
OBJECT_KINDS = ("blob", "chunk", "manifest", "delta", "bundle", "archive")

#: Compression codecs the store understands. ``none`` is recorded when
#: compression did not shrink the payload (honest: never claim savings).
CODECS = ("zstd", "none")

#: Storage tiers, hot first. Lifecycle moves objects down this list.
STORAGE_TIERS = ("hot", "warm", "cold")

#: Evidence categories from the storage-risk table (spec §7). Each maps to
#: a storage policy row (retention + lifecycle).
EVIDENCE_CATEGORIES = (
    "raw_collector_output",
    "asset_observation",
    "binary_artifact",
    "scan_log",
    "crypto_event",
    "performance_metric",
    "report_export",
    "cache_data",
)


class ContentObject(BaseModel, TenantOwned):
    """Metadata for one content-addressed object (bytes live in a body)."""

    __tablename__ = "content_objects"
    __table_args__ = (
        Index("uq_content_objects_tenant_sha", "tenant_id", "sha256", unique=True),
        Index("ix_content_objects_tenant_category", "tenant_id", "category"),
        Index("ix_content_objects_tenant_tier", "tenant_id", "storage_tier"),
    )

    #: Content identity: sha256 of the PLAINTEXT bytes (or of the manifest
    #: plaintext for chunked objects).
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: blob | chunk | manifest | delta | bundle | archive
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="blob")
    #: Evidence category (storage-risk table) driving retention policy.
    category: Mapped[str] = mapped_column(String(40), nullable=False, default="asset_observation")
    #: zstd | none — what the body is compressed with before encryption.
    codec: Mapped[str] = mapped_column(String(12), nullable=False, default="zstd")
    #: Plaintext size (what the consumer of get() receives).
    plain_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: Stored size (compressed, before encryption) — compression savings
    #: are measurable per object for the monitoring report.
    stored_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: Chunk layout for chunked objects: 0 = stored whole. For chunked
    #: objects this lists the chunk content hashes IN ORDER — the manifest
    #: that reassembles the plaintext.
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    chunk_refs: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    #: For chunks: the sha256 of the whole-object row that owns this chunk.
    parent_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    #: hot | warm | cold — object lifecycle state.
    storage_tier: Mapped[str] = mapped_column(String(12), nullable=False, default="hot")
    #: How many rows reference this content (evidence links, deltas, jobs,
    #: snapshots). GC drops a body at 0 and only at 0.
    ref_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    #: Set when the body is dropped by retention (metadata tombstone kept
    #: so the hash chain of history still resolves its identifiers).
    body_dropped_at: Mapped[Optional[object]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ContentObjectBody(BaseModel, TenantOwned):
    """The bytes of a content object (database backend of the object store).

    Ciphertext at rest (db.encryption envelope, tenant-bound). The file
    backend of the object store writes bank-approved object storage
    instead and creates no body row — the metadata row is identical either
    way, which is the point of metadata separation.
    """

    __tablename__ = "content_object_bodies"
    __table_args__ = (
        Index("uq_content_object_bodies_tenant_sha", "tenant_id", "object_sha256", unique=True),
    )

    object_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Envelope-encrypted, compressed bytes.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    bytes_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
