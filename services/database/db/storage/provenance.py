"""Provenance-preserving evidence recording (spec 2.1, critical distinction).

NEVER deduplicate evidence in a way that destroys provenance. Two systems
can have identical evidence bytes but different owners, collection times,
source locations and authorization contexts. The bytes deduplicate in the
content-addressed store; every collection event gets its own
``evidence_content_links`` row — that row is the provenance, and merging
two of them because the hashes match is destroying evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from db.models.evidence_content_link import EvidenceContentLink
from db.storage.cas import ContentAddressedStore, ContentRef
from db.models.base import utcnow


def record_evidence_content(
    session: Session,
    *,
    tenant_id: str,
    data: bytes,
    collected_at: Optional[datetime] = None,
    collector: str,
    source_location: str,
    owner: str,
    authorization_context: Optional[dict[str, Any]] = None,
    evidence_record_id: Optional[str] = None,
    observation_ref: Optional[str] = None,
    category: str = "asset_observation",
    kind: str = "blob",
    store: Optional[ContentAddressedStore] = None,
) -> ContentRef:
    """Store evidence bytes (deduplicated) and record WHO collected them.

    Call this once per collection event — including when the very same
    bytes were collected yesterday. The content reference deduplicates;
    the link row never does. ``evidence_record_id`` ties the content to a
    scan-chain record; ``observation_ref`` covers collection paths outside
    a scan chain (estate observations, job outputs).
    """
    cas = store if store is not None else ContentAddressedStore(session)
    ref = cas.put(tenant_id, data, category=category, kind=kind)
    session.add(EvidenceContentLink(
        tenant_id=tenant_id,
        evidence_record_id=evidence_record_id,
        observation_ref=observation_ref,
        content_sha256=ref.sha256,
        collected_at=collected_at if collected_at is not None else utcnow(),
        collector=collector,
        source_location=source_location,
        owner=owner,
        authorization_context=authorization_context,
    ))
    return ref
