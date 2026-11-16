"""Name the collector authority at collection time — provenance's truth side.

A read-time match against whatever CollectorAuthority happens to exist
later is a guess: an authority approved after the scan blesses a
collection it never covered, and one revoked after the scan denies a
collection that WAS authorized. The honest signal is stamped by the
collection itself: the authority id and approved revision in force when
the scan ran (``scans.collector_authority_id`` / ``_revision``,
migration 0164).

Exact-match only — the authority's ``entry`` must be EXACTLY the scan's
``target_location``. No fuzzy matching, no implied consent. When nothing
matches, the scan is left unstamped and the provenance surface reports
``NOT_RECORDED`` — the honest exception, never a guessed authorization.
"""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select

from db.models.collector_authority import CollectorAuthority
from db.models.scan import Scan


def current_authority(session: Any, *, tenant_id: Any, entry: str) -> Optional[CollectorAuthority]:
    """The newest unrevoked authority covering this exact entry, or None."""
    return session.execute(
        select(CollectorAuthority)
        .where(CollectorAuthority.tenant_id == tenant_id,
               CollectorAuthority.entry == entry,
               CollectorAuthority.revoked_at.is_(None))
        .order_by(CollectorAuthority.approved_at.desc())
    ).scalars().first()


def stamp_collection_authority(session: Any, scan: Scan) -> Optional[CollectorAuthority]:
    """Stamp the authority this collection runs under, at creation time.

    Returns the authority stamped (or None — no covering authority, the
    scan honestly carries no claim). Existing stamps are never
    overwritten: historical evidence keeps what it recorded.
    """
    if scan.collector_authority_id:
        return None
    authority = current_authority(
        session, tenant_id=scan.tenant_id, entry=scan.target_location)
    if authority is None:
        return None
    scan.collector_authority_id = authority.id
    scan.collector_authority_revision = int(authority.revision or 0)
    return authority
