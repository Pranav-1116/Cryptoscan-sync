"""Key-inventory drift: new orphans / unaccounted code keys / removed keys since the previous export scan."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from db.connection.session import Base
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from worker.pipeline.inventory_drift import detect_inventory_drift


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _inv(label, library="ICSF", algorithm="3DES", key_size=112):
    return {"source": {"type": "KEY_INVENTORY", "file_path": "ckds.lst", "line_number": 1}, "crypto": {"algorithm": algorithm, "key_size": key_size},
            "metadata": {"library": library}, "inventory": {"key_label": label, "key_store": "CKDS"}}


def _add_inventory_scan(session, scan_id, when, labels):
    session.add(Scan(id=scan_id, scan_start=when, target_location="file:///drops/keys", target_type="LOCAL_DIRECTORY", status="COMPLETED",
                     statistics={"evidence_sources": {"KEY_INVENTORY": len(labels)}}))
    for i, label in enumerate(labels):
        fd = _inv(label)
        session.add(EvidenceRecord(id=f"{scan_id}-{i}", scan_id=scan_id, content_hash=f"h{scan_id}{i}", chain_hash="c", chain_position=i, algorithm="3DES",
                                   confidence="HIGH", file_path="ckds.lst", line_number=1, finding_data=fd))
    session.commit()


def test_inventory_drift_reports_only_what_is_new():
    session = _session()
    session.add(Scan(id="src", scan_start=datetime(2026, 9, 20, tzinfo=timezone.utc), target_location="https://git/core.git", target_type="GIT_REPOSITORY", status="COMPLETED",
                     statistics={"cascade": {"key_references": [
                         {"kind": "key_alias", "identifier": "PAY.ZPK.ACQ001", "files": 2, "sample_files": ["a.cbl"]},
                         {"kind": "key_alias", "identifier": "ghost-alias", "files": 1, "sample_files": ["b.java"]},
                         {"kind": "env_var", "identifier": "SECRET_KEY", "files": 1, "sample_files": ["c.py"]}]}}))
    session.commit()

    # first export: 2 keys, one consumed, one orphan; code has one unaccounted alias
    _add_inventory_scan(session, "inv-1", datetime(2026, 9, 21, tzinfo=timezone.utc), ["PAY.ZPK.ACQ001", "OLD.ZMK"])
    events = detect_inventory_drift(session, "inv-1")
    kinds = sorted((e["drift_type"], e["severity"]) for e in events)
    assert kinds == [("KEY_ORPHAN", "MEDIUM"), ("KEY_UNACCOUNTED", "HIGH")]
    rec = session.get(Scan, "inv-1").statistics["key_reconciliation"]
    assert rec["summary"]["consumers"] == 1 and rec["orphans"][0]["label"] == "OLD.ZMK" and rec["not_in_inventory"][0]["identifier"] == "ghost-alias"
    assert rec["previous_inventory_scan"] is None and rec["source_scans"] == ["src"]

    # second export: OLD.ZMK retired, a new orphan appears; the unchanged unaccounted alias must not re-alert
    _add_inventory_scan(session, "inv-2", datetime(2026, 9, 25, tzinfo=timezone.utc), ["PAY.ZPK.ACQ001", "NEW.ZPK"])
    events = detect_inventory_drift(session, "inv-2")
    assert sorted(e["drift_type"] for e in events) == ["KEY_INVENTORY_REMOVED", "KEY_ORPHAN"]
    orphan = next(e for e in events if e["drift_type"] == "KEY_ORPHAN")
    assert "NEW.ZPK" in orphan["reason"]
    rows = session.query(DriftEvent).filter(DriftEvent.current_scan_id == "inv-2").all()
    assert {r.drift_type for r in rows} == {"KEY_INVENTORY_REMOVED", "KEY_ORPHAN"} and all(r.baseline_id is None and r.resolution_status == "OPEN" for r in rows)
    removed = next(r for r in rows if r.drift_type == "KEY_INVENTORY_REMOVED")
    assert removed.drift_details["label"] == "OLD.ZMK" and removed.drift_details["previous_scan_id"] == "inv-1"
    rec2 = session.get(Scan, "inv-2").statistics["key_reconciliation"]
    assert rec2["previous_inventory_scan"] == "inv-1" and rec2["new_unaccounted"] == 0 and rec2["summary"]["not_in_inventory"] == 1


def test_inventory_drift_noop_for_code_scans():
    session = _session()
    session.add(Scan(id="code", scan_start=datetime(2026, 9, 25, tzinfo=timezone.utc), target_location="https://git/x.git", target_type="GIT_REPOSITORY", status="COMPLETED", statistics={}))
    session.commit()
    assert detect_inventory_drift(session, "code") == [] and "key_reconciliation" not in (session.get(Scan, "code").statistics or {})
