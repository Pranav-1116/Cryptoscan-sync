"""Evidence chain verification sweep (deep/25 §2.2, round 25).

The report's P0#3: verification primitives all exist —
``ContentHasher.verify_hash``, ``ChainHasher.verify_chain``, the manifest
— but nothing invokes them on a schedule; verification is manual or
API-triggered, so tampering is only caught by whoever remembers to ask.
This sweep is the missing automated job: every monitor tick re-verifies
the newest scans' evidence, end to end, four checks per scan.

Per scan (records ordered by ``chain_position``, soft-deleted tombstones
INCLUDED by design — retracting a finding must never break the chain it
committed to, audit 15/16):

0. **content**: ``ContentHasher.compute_hash(finding_data)`` equals the
   stored ``content_hash`` — catches a tampered payload, the report's
   tamper-table row 1;
1. **chain**: the stored ``chain_hash`` list recomputes from the content
   hashes — catches a rewritten or reordered record;
2. **contiguity**: positions are exactly ``0..n-1`` — a hard-deleted
   record leaves a gap no recompute hides;
3. **manifest pin**: ``sha256`` over the sorted evidence ids equals the
   ``scan.manifest_hash`` the scan committed to — catches a
   delete-and-rechain attack whose remaining hashes are internally
   consistent but no longer what was published.

Alerting is persistent on purpose: unlike an SLA crossing, a broken
evidence chain does not age out — it is a forensic incident that pages
until investigated. One aggregated CRITICAL alert per tick plus one
``evidence.chain_broken`` platform event per broken scan, both bounded.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _verify_scan(session, scan_id: str, records: list[Any]) -> list[str]:
    """All four checks for one scan; returns the (deduped) problem list."""
    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.hashing.content_hasher import ContentHasher

    problems: list[str] = []

    for i, record in enumerate(records):
        try:
            recomputed = ContentHasher.compute_hash(record.finding_data)
        except Exception:  # noqa: BLE001 — a corrupt payload is itself a finding
            problems.append(f"finding_data unverifiable at position {i}")
            continue
        if recomputed != record.content_hash:
            problems.append(f"content_hash mismatch at position {i}")

    content = [r.content_hash for r in records]
    stored = [r.chain_hash or "" for r in records]
    if not ChainHasher.verify_chain(content, stored, str(scan_id)):
        problems.append("chain_hash mismatch")

    if [r.chain_position for r in records] != list(range(len(records))):
        problems.append("chain positions not contiguous 0..n-1")

    if records and records[0].previous_hash is not None:
        problems.append("first record previous_hash not null")
    for i in range(1, len(records)):
        if records[i].previous_hash != records[i - 1].chain_hash:
            problems.append(f"previous_hash broken at position {i}")
            break

    return sorted(set(problems))


def run_evidence_chain_sweep(
    session: Any,
    *,
    now: datetime | None = None,
    on_alert: Callable[[str, str, dict], None] | None = None,
    max_scans: int = 100,
    max_records_per_scan: int = 10_000,
    max_reported: int = 20,
) -> dict[str, Any]:
    """Verify the newest ``max_scans`` scans' evidence chains; alert on any
    breakage. Bounded by construction with explicit truncation flags."""
    from sqlalchemy import desc, func, select

    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan

    now = _aware(now) or datetime.now(timezone.utc)

    # newest scans that actually have evidence, newest first
    scan_rows = (
        session.execute(
            select(EvidenceRecord.scan_id, func.max(EvidenceRecord.created_at).label("latest"))
            .group_by(EvidenceRecord.scan_id)
            .order_by(desc("latest"))
            .limit(max_scans)
        )
        .all()
    )
    scans_truncated = len(scan_rows) == max_scans

    scans_verified = 0
    evidence_verified = 0
    broken: list[dict[str, Any]] = []
    records_truncated = False

    for scan_id, _latest in scan_rows:
        records = list(
            session.execute(
                select(EvidenceRecord)
                .where(EvidenceRecord.scan_id == scan_id)
                .order_by(EvidenceRecord.chain_position)
            )
            .scalars()
            .all()
        )
        truncated = len(records) > max_records_per_scan
        records_truncated = records_truncated or truncated
        if truncated:
            records = records[:max_records_per_scan]

        problems = _verify_scan(session, scan_id, records)

        # manifest pin — only when the scan committed to one
        scan = session.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if scan is not None and scan.manifest_hash and records:
            pin = hashlib.sha256(
                "".join(sorted(str(r.id) for r in records)).encode("utf-8")
            ).hexdigest()
            if pin != scan.manifest_hash:
                problems = sorted(set(problems + ["manifest hash pin mismatch (evidence id set changed)"]))

        scans_verified += 1
        evidence_verified += len(records)
        if problems:
            entry: dict[str, Any] = {
                "scan_id": str(scan_id),
                "records": len(records),
                "problems": problems,
            }
            if truncated:
                entry["truncated"] = True
            broken.append(entry)

    reported = broken[:max_reported]
    broken_truncated = len(broken) > max_reported

    if broken:
        issue = (
            f"evidence chain verification: {len(broken)} broken scan(s) — "
            + "; ".join(
                f"{entry['scan_id']} ({', '.join(entry['problems'])})" for entry in reported
            )
            + ("; more truncated" if broken_truncated else "")
        )
        payload = {
            "scans_verified": scans_verified,
            "evidence_verified": evidence_verified,
            "broken_scans": len(broken),
            "broken": reported,
            "truncated": broken_truncated,
        }
        if on_alert is not None:
            try:
                on_alert("evidence-chain", issue, payload)
            except Exception:  # noqa: BLE001 — alerting must not kill the sweep
                logger.warning("evidence_chain_alert_failed", exc_info=True)
        for entry in reported:
            try:
                from api.events.platform_events import emit_platform_event

                emit_platform_event(
                    "evidence.chain_broken",
                    f"evidence chain broken for scan {entry['scan_id']}",
                    {"source": "monitor-sweep", **entry},
                    target_name="evidence",
                )
            except Exception:
                logger.debug("evidence_chain_event_skipped", exc_info=True)
        logger.error(
            "evidence_chain_broken",
            extra={"broken_scans": len(broken), "verified": scans_verified},
        )

    return {
        "scans_considered": len(scan_rows),
        "scans_verified": scans_verified,
        "evidence_verified": evidence_verified,
        "broken_scans": len(broken),
        "broken": reported,
        "truncated": scans_truncated or records_truncated or broken_truncated,
    }
