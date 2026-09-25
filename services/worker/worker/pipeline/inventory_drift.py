"""Key-inventory drift: reconcile a key-export scan against the newest source scans and raise drift events
for what is *new* since the previous inventory scan of the same drop.

* ``KEY_ORPHAN``       (MEDIUM) — an inventory key no scanned repository references any more / yet
* ``KEY_UNACCOUNTED``  (HIGH)   — an alias or keystore file the code uses that no inventory export lists
* ``KEY_INVENTORY_REMOVED`` (LOW) — a key that was in the previous export and is gone (retired or lost)

Needs no approved baseline: the previous inventory scan of the same target is the reference; on the first
scan everything is new and is reported once. The reconciliation itself is stored in
``Scan.statistics.key_reconciliation`` (bounded) so the UI does not have to recompute it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

MAX_EVENTS = 200
MAX_STORED = 500


def _inventory_findings(session, scan_id: str) -> list[dict]:
    from sqlalchemy import select

    from db.models.evidence_record import EvidenceRecord

    rows = session.execute(select(EvidenceRecord.finding_data).where(EvidenceRecord.scan_id == scan_id)).scalars()
    return [fd for fd in rows if ((fd or {}).get("source") or {}).get("type") == "KEY_INVENTORY"]


def _source_key_references(session, exclude_scan_id: str) -> tuple[list[tuple[str, dict]], list[str]]:
    from db.models.scan import Scan

    refs, used, seen_targets = [], [], set()
    for s in session.query(Scan).filter(Scan.status == "COMPLETED", Scan.id != exclude_scan_id).order_by(Scan.scan_start.desc()).limit(200).all():
        kr = ((s.statistics or {}).get("cascade") or {}).get("key_references")
        if s.target_location in seen_targets or not kr:
            continue
        seen_targets.add(s.target_location)
        used.append(s.id)
        refs.extend((s.id, r) for r in kr)
    return refs, used


def _previous_inventory_scan(session, scan) -> Any:
    from db.models.scan import Scan

    q = (session.query(Scan).filter(Scan.status == "COMPLETED", Scan.target_location == scan.target_location, Scan.id != scan.id)
         .order_by(Scan.scan_start.desc()))
    for prev in q.limit(50).all():
        if ((prev.statistics or {}).get("evidence_sources") or {}).get("KEY_INVENTORY"):
            return prev
    return None


def detect_inventory_drift(session, scan_id: str) -> list[dict]:
    """Run after the evidence load. Returns the drift events it added (also written to ``drift_events``)."""
    from sqlalchemy.orm.attributes import flag_modified

    from db.models.drift_event import DriftEvent
    from db.models.scan import Scan
    from evidence.intelligence.key_reconciliation import reconcile_key_inventory

    scan = session.get(Scan, scan_id)
    if scan is None:
        return []
    inventory = _inventory_findings(session, scan_id)
    if not inventory:
        return []
    refs, source_ids = _source_key_references(session, scan_id)
    rec = reconcile_key_inventory(inventory, refs)

    prev = _previous_inventory_scan(session, scan)
    prev_rec = ((prev.statistics or {}).get("key_reconciliation") or {}) if prev is not None else {}
    prev_orphans = {(o["system"], o["label"]) for o in prev_rec.get("orphans") or []}
    prev_unaccounted = {(n["kind"], n["identifier"]) for n in prev_rec.get("not_in_inventory") or []}
    prev_labels = set(prev_rec.get("labels") or [])
    cur_labels = sorted({(f.get("inventory") or {}).get("key_label") for f in inventory if (f.get("inventory") or {}).get("key_label")})

    now = datetime.now(timezone.utc)
    events: list[dict] = []

    def _emit(drift_type: str, severity: str, reason: str, details: dict) -> None:
        if len(events) >= MAX_EVENTS:
            return
        session.add(DriftEvent(baseline_id=None, current_scan_id=scan_id, detected_at=now, drift_type=drift_type, severity=severity,
                               drift_details={"change_type": drift_type, "reason": reason, **details}, resolution_status="OPEN"))
        events.append({"drift_type": drift_type, "severity": severity, "reason": reason, "algorithm": details.get("algorithm")})

    for o in rec["orphans"]:
        if (o["system"], o["label"]) not in prev_orphans:
            _emit("KEY_ORPHAN", "MEDIUM", f"{o['system']} key {o['label']} is referenced by no scanned repository",
                  {"system": o["system"], "label": o["label"], "algorithm": o.get("algorithm"), "key_size": o.get("key_size"), "key_store": o.get("key_store")})
    for n in rec["not_in_inventory"]:
        if (n["kind"], n["identifier"]) not in prev_unaccounted:
            _emit("KEY_UNACCOUNTED", "HIGH", f"{n['kind']} {n['identifier']} is used in code but listed in no key inventory",
                  {"kind": n["kind"], "identifier": n["identifier"], "files": n.get("files"), "sample_files": n.get("sample_files"), "source_scan_id": n.get("scan_id")})
    if prev is not None:
        for label in sorted(prev_labels - set(cur_labels)):
            _emit("KEY_INVENTORY_REMOVED", "LOW", f"key {label} was in the previous export and is no longer listed", {"label": label, "previous_scan_id": prev.id})

    stats = dict(scan.statistics or {})
    stats["key_reconciliation"] = {
        "summary": rec["summary"],
        "source_scans": source_ids,
        "previous_inventory_scan": prev.id if prev is not None else None,
        "new_orphans": sum(1 for e in events if e["drift_type"] == "KEY_ORPHAN"),
        "new_unaccounted": sum(1 for e in events if e["drift_type"] == "KEY_UNACCOUNTED"),
        "removed": sum(1 for e in events if e["drift_type"] == "KEY_INVENTORY_REMOVED"),
        "orphans": [{k: o.get(k) for k in ("system", "label", "algorithm", "key_size", "key_store")} for o in rec["orphans"][:MAX_STORED]],
        "not_in_inventory": [{k: n.get(k) for k in ("kind", "identifier", "files", "scan_id")} for n in rec["not_in_inventory"][:MAX_STORED]],
        "labels": cur_labels[:5000],
        "events_truncated": max(0, len(rec["orphans"]) + len(rec["not_in_inventory"]) - MAX_EVENTS) if len(events) >= MAX_EVENTS else 0,
    }
    scan.statistics = stats
    flag_modified(scan, "statistics")
    session.flush()
    logger.info("inventory_drift_done", extra={"scan_id": scan_id, "events": len(events), "orphans": rec["summary"]["orphans"],
                                              "not_in_inventory": rec["summary"]["not_in_inventory"]})
    return events
