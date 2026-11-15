"""Content-addressed evidence store: bytes stored once, provenance never merged.

Spec 2.1: identify evidence using cryptographic hashes (SHA-256 of the
plaintext bytes), deduplicate identical evidence, compress (zstd), chunk
large evidence into manageable pieces, keep searchable metadata separate
from the large bytes (the object-store backend).

Two contracts dominate the design:

1. **Deduplication stops at the bytes.** Identical bytes occupy one
   object per tenant. Who collected them, when, from where and under whose
   authorization lives in ``evidence_content_links`` and is NEVER merged —
   see db/storage/provenance.py.
2. **Tenant identity is part of the content address.** Two tenants
   storing the same bytes store two objects. Deduplication must never
   answer "which other bank has these bytes?".

Every :meth:`ContentAddressedStore.get` verifies the content hash — the
store cannot silently return wrong bytes, and restore testing is the same
code path an ordinary read uses.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from db import encryption
from db.models.content_object import ContentObject, ContentObjectBody
from db.storage.compression import compress, decompress

logger = logging.getLogger(__name__)

#: Objects larger than this are split into chunks (spec: "chunking — split
#: large evidence into manageable chunks"). 256 KiB keeps a chunk small
#: enough to move a piece at a time and large enough to amortize rows.
CHUNK_SIZE = 256 * 1024


class ContentGoneError(RuntimeError):
    """The metadata exists but retention dropped the bytes (tombstone)."""


class ContentCorruptionError(RuntimeError):
    """Stored bytes failed their content-hash check on read."""


@dataclass(frozen=True)
class ContentRef:
    """Result of a put: where the content lives and whether it was new."""

    sha256: str
    plain_size: int
    stored_size: int
    codec: str
    kind: str
    chunk_count: int
    deduped: bool


class ObjectStore(Protocol):
    """Where ciphertext bodies live: database rows or object storage.

    The metadata row (``content_objects``) is always in PostgreSQL; the
    bytes go wherever the deployment's bank-approved storage is. Metadata
    separation is what lets listing/searching the evidence estate never
    drag the large files through the database.
    """

    def put(self, tenant_id: str, sha256: str, ciphertext: bytes) -> None: ...

    def get(self, tenant_id: str, sha256: str) -> bytes: ...

    def delete(self, tenant_id: str, sha256: str) -> None: ...


class DbObjectStore:
    """Bodies in PostgreSQL (``content_object_bodies``), ciphertext at rest."""

    def __init__(self, session: Session):
        self.session = session

    def put(self, tenant_id: str, sha256: str, ciphertext: bytes) -> None:
        self.session.add(ContentObjectBody(
            tenant_id=tenant_id, object_sha256=sha256,
            ciphertext=ciphertext, bytes_size=len(ciphertext),
        ))

    def get(self, tenant_id: str, sha256: str) -> bytes:
        row = self.session.execute(
            select(ContentObjectBody).where(
                ContentObjectBody.tenant_id == tenant_id,
                ContentObjectBody.object_sha256 == sha256,
            )
        ).scalar_one_or_none()
        if row is None:
            raise ContentGoneError(f"no stored body for {sha256[:16]}…")
        return row.ciphertext

    def delete(self, tenant_id: str, sha256: str) -> None:
        row = self.session.execute(
            select(ContentObjectBody).where(
                ContentObjectBody.tenant_id == tenant_id,
                ContentObjectBody.object_sha256 == sha256,
            )
        ).scalar_one_or_none()
        if row is not None:
            self.session.delete(row)


class FileObjectStore:
    """Bodies in bank-approved object storage: a content-addressed directory.

    Layout: ``{root}/{tenant}/{sha[:2]}/{sha}.bin`` — one file per object,
    addressed by content hash, written atomically. The directory is the
    object-storage mount point (SMB/NFS/S3-fuse all look like this).
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _path(self, tenant_id: str, sha256: str) -> Path:
        safe_tenant = "".join(c for c in (tenant_id or "platform") if c.isalnum() or c in "-_")
        return self.root / safe_tenant / sha256[:2] / f"{sha256}.bin"

    def put(self, tenant_id: str, sha256: str, ciphertext: bytes) -> None:
        path = self._path(tenant_id, sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(ciphertext)
        tmp.replace(path)  # atomic: a torn write is never visible

    def get(self, tenant_id: str, sha256: str) -> bytes:
        path = self._path(tenant_id, sha256)
        if not path.exists():
            raise ContentGoneError(f"no stored body for {sha256[:16]}…")
        return path.read_bytes()

    def delete(self, tenant_id: str, sha256: str) -> None:
        path = self._path(tenant_id, sha256)
        if path.exists():
            path.unlink()


class S3ObjectStore:
    """Bodies in a bank-controlled S3-compatible object store.

    The spec names the technology for large evidence artifacts and exports:
    "bank-controlled S3-compatible storage or an equivalent". This is the
    S3-compatible form of the ObjectStore protocol — S3 itself, MinIO, Ceph
    RGW or any bank appliance speaking the same API.

    The client is injected (boto3-shaped: put_object / get_object /
    delete_object), so the bank's endpoint, credentials and signing stay
    entirely in the bank's hands — this class never opens a network
    connection of its own choosing and never embeds a credential. Key
    layout matches FileObjectStore (``{tenant}/{sha[:2]}/{sha}.bin``), so
    the same content address works over either backend.

    A missing body raises ``ContentGoneError`` exactly like the other
    stores; corruption is caught one layer up where the SHA-256 is checked
    against the content address (a store that re-hash-verified would do the
    work twice).
    """

    def __init__(self, client: Any, bucket: str, *, prefix: str = ""):
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def _key(self, tenant_id: str, sha256: str) -> str:
        safe_tenant = "".join(c for c in (tenant_id or "platform") if c.isalnum() or c in "-_")
        key = f"{safe_tenant}/{sha256[:2]}/{sha256}.bin"
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, tenant_id: str, sha256: str, ciphertext: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=self._key(tenant_id, sha256),
                               Body=ciphertext)

    def get(self, tenant_id: str, sha256: str) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(tenant_id, sha256))
        except Exception as exc:  # noqa: BLE001 — translated to the store contract
            name = type(exc).__name__
            if "NoSuchKey" in name or "404" in str(exc) or "NotFound" in name:
                raise ContentGoneError(f"no stored body for {sha256[:16]}…") from exc
            raise
        body = response["Body"]
        return body.read() if hasattr(body, "read") else bytes(body)

    def delete(self, tenant_id: str, sha256: str) -> None:
        # S3 delete is idempotent (204 whether or not the key existed) —
        # same contract as FileObjectStore.delete.
        self.client.delete_object(Bucket=self.bucket, Key=self._key(tenant_id, sha256))


def sha256_hex(data: bytes) -> str:
    """The content address: SHA-256 of the plaintext bytes."""
    return hashlib.sha256(data).hexdigest()


class ContentAddressedStore:
    """The content-addressed store over a session and an object backend."""

    def __init__(self, session: Session, object_store: Optional[ObjectStore] = None,
                 *, enforce_quotas: bool = True):
        self.session = session
        self.objects: ObjectStore = object_store if object_store is not None else DbObjectStore(session)
        self.enforce_quotas = enforce_quotas

    # ------------------------------------------------------------------ put
    def put(self, tenant_id: str, data: bytes, *, category: str = "asset_observation",
            kind: str = "blob", compress_content: bool = True,
            job_id: Optional[str] = None) -> ContentRef:
        """Store bytes once (per tenant) and return their content reference.

        Identical bytes submitted next week hit the existing object and only
        bump ``ref_count`` — the "RSA-2048 discovered on Monday, Tuesday,
        Wednesday" case stores one object and three references.
        """
        digest = sha256_hex(data)
        existing = self._object(tenant_id, digest)
        if existing is not None and existing.body_dropped_at is None:
            existing.ref_count += 1
            return ContentRef(digest, existing.plain_size, existing.stored_size,
                              existing.codec, existing.kind, existing.chunk_count,
                              deduped=True)

        if self.enforce_quotas:
            from db.storage.quotas import check_quota
            check_quota(self.session, tenant_id, add_bytes=len(data), job_id=job_id)

        if len(data) > CHUNK_SIZE:
            return self._put_chunked(tenant_id, data, category=category, kind=kind,
                                     compress_content=compress_content)
        stored, codec = compress(data, enabled=compress_content)
        self._store_body(tenant_id, digest, stored)
        if existing is not None:
            # Tombstone resurrection: retention dropped the body, but the
            # content came in again. Store it again under the same address —
            # the metadata row (and its history) is never rewritten.
            existing.body_dropped_at = None
            existing.ref_count += 1
            existing.stored_size = len(stored)
            return ContentRef(digest, len(data), len(stored), codec, existing.kind,
                              0, deduped=True)
        self.session.add(ContentObject(
            tenant_id=tenant_id, sha256=digest, kind=kind, category=category,
            codec=codec, plain_size=len(data), stored_size=len(stored),
            chunk_count=0, storage_tier="hot", ref_count=1,
        ))
        return ContentRef(digest, len(data), len(stored), codec, kind, 0, deduped=False)

    def _put_chunked(self, tenant_id: str, data: bytes, *, category: str, kind: str,
                     compress_content: bool) -> ContentRef:
        digest = sha256_hex(data)
        parent = self._object(tenant_id, digest)
        chunk_refs: list[dict] = []
        total_stored = 0
        for start in range(0, len(data), CHUNK_SIZE):
            piece = data[start:start + CHUNK_SIZE]
            piece_sha = sha256_hex(piece)
            piece_obj = self._object(tenant_id, piece_sha)
            if piece_obj is not None and piece_obj.body_dropped_at is None:
                piece_obj.ref_count += 1
                total_stored += piece_obj.stored_size
            else:
                stored, codec = compress(piece, enabled=compress_content)
                self._store_body(tenant_id, piece_sha, stored)
                if piece_obj is not None:  # tombstone resurrection
                    piece_obj.body_dropped_at = None
                    piece_obj.ref_count += 1
                    piece_obj.stored_size = len(stored)
                else:
                    self.session.add(ContentObject(
                        tenant_id=tenant_id, sha256=piece_sha, kind="chunk",
                        category=category, codec=codec, plain_size=len(piece),
                        stored_size=len(stored), chunk_count=0,
                        parent_sha256=digest, storage_tier="hot", ref_count=1,
                    ))
                total_stored += len(stored)
            chunk_refs.append({"sha256": piece_sha, "plain_size": len(piece)})
        if parent is not None:
            # Tombstone resurrection: the content came in again — store it
            # again under the same address; the metadata row is never new.
            parent.body_dropped_at = None
            parent.ref_count += 1
            parent.stored_size = total_stored
            parent.chunk_refs = chunk_refs
            parent.chunk_count = len(chunk_refs)
            deduped = True
        else:
            self.session.add(ContentObject(
                tenant_id=tenant_id, sha256=digest, kind=kind, category=category,
                codec="none", plain_size=len(data), stored_size=total_stored,
                chunk_count=len(chunk_refs), chunk_refs=chunk_refs,
                storage_tier="hot", ref_count=1,
            ))
            deduped = False
        return ContentRef(digest, len(data), total_stored, "none", kind,
                          len(chunk_refs), deduped=deduped)

    # ------------------------------------------------------------------ get
    def get(self, tenant_id: str, sha256: str) -> bytes:
        """Read content back — decrypt, decompress and VERIFY the address."""
        obj = self._object(tenant_id, sha256)
        if obj is None:
            raise ContentGoneError(f"unknown content {sha256[:16]}…")
        if obj.body_dropped_at is not None:
            raise ContentGoneError(
                f"content {sha256[:16]}… was dropped by retention (metadata kept)")
        if obj.chunk_count and obj.chunk_refs:
            pieces = []
            for ref in obj.chunk_refs:
                piece = self._read_body(tenant_id, ref["sha256"], obj.category)
                if sha256_hex(piece) != ref["sha256"]:
                    raise ContentCorruptionError(f"chunk {ref['sha256'][:16]}… failed its hash")
                pieces.append(piece)
            data = b"".join(pieces)
        else:
            data = self._read_body(tenant_id, sha256, obj.category)
        if sha256_hex(data) != sha256:
            raise ContentCorruptionError(f"content {sha256[:16]}… failed its hash on read")
        return data

    def _read_body(self, tenant_id: str, sha256: str, category: str) -> bytes:
        obj = self._object(tenant_id, sha256)
        if obj is None or obj.body_dropped_at is not None:
            raise ContentGoneError(f"no stored body for {sha256[:16]}…")
        ciphertext = self.objects.get(tenant_id, sha256)
        compressed = encryption.unprotect(ciphertext, tenant_id=tenant_id)
        return decompress(compressed, obj.codec)

    # ------------------------------------------------------- refcount / delete
    def retain(self, tenant_id: str, sha256: str) -> None:
        obj = self._object(tenant_id, sha256)
        if obj is not None:
            obj.ref_count += 1

    def release(self, tenant_id: str, sha256: str) -> None:
        """Drop one reference. GC eligibility is ref_count == 0 and only 0."""
        obj = self._object(tenant_id, sha256)
        if obj is not None and obj.ref_count > 0:
            obj.ref_count -= 1

    def delete_object(self, tenant_id: str, sha256: str) -> None:
        """Remove object metadata + bodies (GC/retention use; audited by caller)."""
        obj = self._object(tenant_id, sha256)
        if obj is None:
            return
        if obj.chunk_count and obj.chunk_refs:
            for ref in obj.chunk_refs:
                chunk = self._object(tenant_id, ref["sha256"])
                if chunk is None:
                    continue
                if chunk.ref_count > 1:
                    # Shared chunk (another object reuses it): drop only the
                    # parent's reference. Deleting shared bytes under a
                    # sibling's feet is data loss.
                    chunk.ref_count -= 1
                else:
                    self._delete_one(tenant_id, ref["sha256"])
        self._delete_one(tenant_id, sha256)

    def _delete_one(self, tenant_id: str, sha256: str) -> None:
        obj = self._object(tenant_id, sha256)
        if obj is not None:
            self.session.delete(obj)
        self.objects.delete(tenant_id, sha256)

    # ---------------------------------------------------------------- internals
    def _object(self, tenant_id: str, sha256: str) -> Optional[ContentObject]:
        return self.session.execute(
            select(ContentObject).where(
                ContentObject.tenant_id == tenant_id,
                ContentObject.sha256 == sha256,
            )
        ).scalar_one_or_none()

    def _store_body(self, tenant_id: str, sha256: str, compressed: bytes) -> None:
        ciphertext = encryption.protect(compressed, tenant_id=tenant_id)
        self.objects.put(tenant_id, sha256, ciphertext)
