"""Content-addressed artifact blob store — evidence bytes stored once.

Every resubmission of the same artifact used to store its bytes again; a
platform that collects continuously cannot afford that. The blob store is
the deduplication: (tenant_id, sha256) is unique, the bytes live here
exactly once (envelope-encrypted, tenant-bound), and job rows reference
the content by its hash instead of carrying copies.

The tenant is part of the identity on purpose: two tenants uploading the
same file store two blobs. Deduplication never becomes a cross-tenant
side channel (\"which other bank has this file?\" must be unanswerable).
"""

from __future__ import annotations

from sqlalchemy import BigInteger, Index, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantOwned


class BinaryArtifactBlob(BaseModel, TenantOwned):
    __tablename__ = "binary_artifact_blobs"
    __table_args__ = (
        Index("uq_binary_artifact_blobs_tenant_sha", "tenant_id", "sha256",
              unique=True),
    )

    #: Content identity: sha256 of the PLAINTEXT bytes.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The bytes, envelope-encrypted (db.encryption) — ciphertext at rest.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    bytes_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: How many job rows reference this content. A blob is droppable at 0
    #: and only at 0 — the retention sweep checks the count, never guesses.
    ref_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
