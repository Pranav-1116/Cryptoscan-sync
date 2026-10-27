"""Round 25 (deep/25 §2.2, P0#3): automated evidence chain verification.

Records are built through the REAL EvidencePipeline (content hash, chain
hash, manifest pin all genuine), then tampered with in the specific ways
the report's tamper-detection table describes — the sweep must catch
each one, alert, and emit the platform event. Deterministic; no network.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from worker.monitor.evidence_chain_sweep import run_evidence_chain_sweep

NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

FINDINGS = [
    {
        "crypto": {"algorithm": "RSA", "key_size": 2048, "operation": "KEY_GENERATION"},
        "source": {"file_path": "src/A.java", "line_number": 42},
        "metadata": {"confidence": "HIGH"},
    },
    {
        "crypto": {"algorithm": "AES", "key_size": 256, "mode": "GCM"},
        "source": {"file_path": "src/B.java", "line_number": 7},
        "metadata": {"confidence": "HIGH"},
    },
    {
        "crypto": {"algorithm": "SHA-256"},
        "source": {"file_path": "src/C.java", "line_number": 3},
        "metadata": {"confidence": "MEDIUM"},
    },
]


def _session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _load_scan(session, scan_id, findings, when=NOW):
    """Persist one scan through the real pipeline: genuine content hashes,
    chain hashes and a manifest pin, exactly as stage_load stores them."""
    from evidence.core.pipeline import EvidencePipeline

    pipeline = EvidencePipeline(scan_session_id=scan_id)
    records, manifest = pipeline.process(findings=findings, scan_id=scan_id)
    session.add(
        Scan(
            id=scan_id,
            scan_start=when,
            target_location=f"repo-{scan_id}",
            target_type="GIT_REPOSITORY",
            status="COMPLETED",
            manifest_hash=manifest.manifest_hash,
        )
    )
    for record in records:
        finding = record.finding
        crypto = finding.get("crypto") or {}
        source = finding.get("source") or {}
        session.add(
            EvidenceRecord(
                id=record.evidence_id,
                scan_id=scan_id,
                content_hash=record.content_hash,
                chain_hash=record.chain_hash,
                chain_position=record.chain_position,
                previous_hash=record.previous_hash,
                algorithm=crypto.get("algorithm") or "UNKNOWN",
                key_size=crypto.get("key_size"),
                file_path=source.get("file_path") or "unknown",
                line_number=int(source.get("line_number") or 0),
                confidence="HIGH",
                finding_data=finding,
            )
        )
    session.commit()
    return records, manifest


def _events(monkeypatch):
    import api.events.platform_events as module

    captured: list[tuple[str, str]] = []
    monkeypatch.setattr(module, "emit_platform_event", lambda *a, **k: captured.append((a[0], a[1])))
    return captured


# --------------------------------------------------------------------- #
# Intact chain
# --------------------------------------------------------------------- #

def test_sweep_verifies_intact_chain_without_alerts():
    session = _session()
    records, _manifest = _load_scan(session, "scan-ok", FINDINGS)

    alerts: list[tuple[str, str]] = []
    result = run_evidence_chain_sweep(
        session, now=NOW, on_alert=lambda name, issue, payload: alerts.append((name, issue))
    )

    assert result["scans_verified"] == 1
    assert result["evidence_verified"] == len(records)
    assert result["broken_scans"] == 0
    assert result["broken"] == []
    assert result["truncated"] is False
    assert alerts == []


def test_sweep_considers_newest_scans_bounded():
    session = _session()
    for i in range(3):
        _load_scan(session, f"scan-{i}", FINDINGS, when=NOW - timedelta(hours=i))

    result = run_evidence_chain_sweep(session, now=NOW, max_scans=2)

    assert result["scans_considered"] == 2
    assert result["scans_verified"] == 2
    assert result["truncated"] is True  # explicit, not silent


def test_sweep_empty_estate_is_honest_zero():
    session = _session()
    result = run_evidence_chain_sweep(session, now=NOW)
    assert result == {
        "scans_considered": 0,
        "scans_verified": 0,
        "evidence_verified": 0,
        "broken_scans": 0,
        "broken": [],
        "truncated": False,
    }


# --------------------------------------------------------------------- #
# Tamper detection (deep/25 §6 table, one test per attack row)
# --------------------------------------------------------------------- #

def test_tampered_finding_data_is_detected(monkeypatch):
    """Row 1: modify EvidenceRecord.finding_data -> content hash mismatch."""
    session = _session()
    records, _ = _load_scan(session, "scan-tamper", FINDINGS)
    captured = _events(monkeypatch)

    victim = session.get(EvidenceRecord, records[1].evidence_id)
    victim.finding_data = dict(victim.finding_data or {}, crypto={"algorithm": "ChaCha20"})
    session.commit()

    alerts: list[tuple[str, str]] = []
    result = run_evidence_chain_sweep(
        session, now=NOW, on_alert=lambda name, issue, payload: alerts.append((name, issue))
    )

    assert result["broken_scans"] == 1
    entry = result["broken"][0]
    assert entry["scan_id"] == "scan-tamper"
    assert "content_hash mismatch at position 1" in entry["problems"]
    assert alerts and alerts[0][0] == "evidence-chain"
    assert ("evidence.chain_broken", "evidence chain broken for scan scan-tamper") in captured


def test_deleted_record_leaves_detectable_gap():
    """Row 2: delete EvidenceRecord -> position gap + manifest pin mismatch
    (an attacker who recomputes the surviving chain still cannot reproduce
    the manifest hash the scan committed to)."""
    session = _session()
    records, _ = _load_scan(session, "scan-gap", FINDINGS)

    victim = session.get(EvidenceRecord, records[1].evidence_id)
    session.delete(victim)
    session.commit()

    result = run_evidence_chain_sweep(session, now=NOW)

    assert result["broken_scans"] == 1
    problems = result["broken"][0]["problems"]
    assert "chain positions not contiguous 0..n-1" in problems
    assert "manifest hash pin mismatch (evidence id set changed)" in problems


def test_rewritten_chain_hash_is_detected():
    """Row 4's class: a chain_hash edited in place stops recomputing."""
    session = _session()
    records, _ = _load_scan(session, "scan-rewrite", FINDINGS)

    victim = session.get(EvidenceRecord, records[0].evidence_id)
    victim.chain_hash = "f" * 64
    session.commit()

    result = run_evidence_chain_sweep(session, now=NOW)
    assert result["broken_scans"] == 1
    assert "chain_hash mismatch" in result["broken"][0]["problems"]


def test_soft_deleted_tombstone_does_not_break_the_chain():
    """Audit 15/16: retraction is a tombstone, not a removal — the record
    stays in the chain it committed to, so verification must stay green."""
    session = _session()
    records, _ = _load_scan(session, "scan-retract", FINDINGS)

    victim = session.get(EvidenceRecord, records[2].evidence_id)
    victim.deleted_at = NOW
    victim.deleted_by = "auditor"
    victim.delete_reason = "false positive"
    session.commit()

    result = run_evidence_chain_sweep(session, now=NOW)
    assert result["broken_scans"] == 0
    assert result["evidence_verified"] == 3


# --------------------------------------------------------------------- #
# Monitor wiring (tick outcome carries the sweep)
# --------------------------------------------------------------------- #

def test_monitor_tick_includes_evidence_chain_outcome(monkeypatch):
    session = _session()
    _load_scan(session, "scan-wire", FINDINGS)
    _events(monkeypatch)

    from worker.monitor.engine import MonitorEngine

    engine = MonitorEngine(
        session, runners={}, clock=lambda: NOW, watch_enabled=False,
        run_reports=False, run_backups=False,
    )
    outcome = engine.tick()

    summary = outcome["evidence_chain"]
    assert summary["scans_verified"] == 1
    assert summary["evidence_verified"] == 3
    assert summary["broken_scans"] == 0


def test_monitor_tick_isolates_evidence_chain_failure():
    """A sweep crash must not stop the rest of the tick (R24 rule)."""
    from worker.monitor import engine as engine_module
    from worker.monitor.engine import MonitorEngine

    session = _session()

    def _boom(*a, **k):
        raise RuntimeError("chain verifier exploded")

    original = engine_module.__dict__.get("run_evidence_chain_sweep")
    # the tick imports the sweep lazily — patch the module it imports from
    import worker.monitor.evidence_chain_sweep as sweep_module

    monkey_target = sweep_module.run_evidence_chain_sweep
    sweep_module.run_evidence_chain_sweep = _boom
    try:
        engine = MonitorEngine(
            session, runners={}, clock=lambda: NOW, watch_enabled=False,
            run_reports=False, run_backups=False,
        )
        outcome = engine.tick()
    finally:
        sweep_module.run_evidence_chain_sweep = monkey_target
        if original is not None:
            engine_module.run_evidence_chain_sweep = original

    assert outcome["evidence_chain"]["status"] == "ERROR"
    assert "RuntimeError" in outcome["evidence_chain"]["error"]
    # the tick itself completed
    assert outcome["ran"] == 0
