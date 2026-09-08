"""Unified Scan Orchestrator tests — scope → target / credential planning and
the fail-closed "no authorized scope" gate. Pure logic, no DB, no AI."""

from __future__ import annotations

from api.live_scan.orchestrator import ScanOrchestrator, ScanPhase


def _org(name="Acme", oid="o1"):
    return {"id": oid, "name": name}


def _scope():
    return [
        {"kind": "network", "target": "10.0.0.0/8", "enabled": True, "detail": {}},
        {"kind": "network", "target": "gateway.example.com:443", "enabled": True, "detail": {}},
        {"kind": "application", "target": "local://demo/vulnerable-app", "enabled": True, "detail": {}},
        {"kind": "cloud", "target": "aws:123456789012", "enabled": True, "detail": {}},
        {"kind": "hardware", "target": "hsm-bank-01", "enabled": True, "detail": {}},
    ]


def _connectors():
    return [
        {"kind": "aws", "method": "iam_role", "mode": "passive", "status": "connected",
         "config": {}, "agent_id": "a1"},
        {"kind": "network", "method": "api", "mode": "passive", "status": "connected",
         "config": {}, "agent_id": "n1"},
        {"kind": "hsm", "method": "agent", "mode": "passive", "status": "configured",
         "config": {}, "agent_id": "h1"},
    ]


def _orch() -> ScanOrchestrator:
    return ScanOrchestrator()


def test_plan_resolves_scope_to_targets_and_credentials():
    targets, credentials = _orch()._plan(_org(), _scope(), _connectors(), [])
    # network host:port becomes a probe target; CIDR stays for discovery
    assert "gateway.example.com:443" in targets["network"]
    assert "10.0.0.0/8" in targets["network_scope"]
    assert "local://demo/vulnerable-app" in targets["source"]
    # hardware host-set fallback is added
    assert "host" in targets["hardware"]
    # credentials derived from configured connectors
    assert credentials.get("network") is True
    assert credentials.get("cloud") is True
    assert credentials.get("vendor") is True   # auto-derived from assets
    assert credentials.get("crypto") is True


def test_plan_empty_scope_is_deny_all():
    targets, credentials = _orch()._plan(_org(), [], [], [])
    assert not any(targets.values())  # fail-closed: no authorized targets


def test_fail_closed_when_no_scope():
    run = _orch().start(_org(), [], [], [])
    assert run.scope_validated is False
    assert run.status == "failed"
    assert "authorized scope" in (run.error or "")
    assert run.phase == ScanPhase.FAILED.value


def test_scan_id_non_ascii_code_final():
    from api.live_scan.orchestrator import SCAN_ID_FORMAT
    assert "{" in SCAN_ID_FORMAT       # format template, e.g. SCAN-2026-000001
    assert SCAN_ID_FORMAT.startswith("SCAN-")


def test_next_scan_id_continues_sequence_when_db_available():
    """Scan ids must stay unique across restarts — the persisted counter wins."""
    class _FakeRow:
        key = "scan_seq"
        value = "0"
        updated_by = None

    class _FakeQuery:
        def __init__(self): self._row = None
        def one_or_none(self): return self._row

    class _FakeDb:
        def __init__(self):
            self.query_calls = 0
            self._q = _FakeQuery()
        def query(self, model):
            assert model.__name__ == "AppSetting"
            self.query_calls += 1
            return self._q
        def add(self, row): self._q._row = row
        def commit(self): pass

    db = _FakeDb()
    orch = _orch()
    # locate the scan_seq row by proving the AppSetting symbol resolves lazily
    import api.live_scan.orchestrator as o
    assert o.SCAN_ID_FORMAT.startswith("SCAN-")
    first = orch._next_scan_id(db=db)
    second = orch._next_scan_id(db=db)
    assert first.endswith("000001")
    assert second.endswith("000002")


def test_collapse_scan_events_rebuilds_run_history():
    from api.live_scan.orchestrator import collapse_scan_events

    events = [
        {"event_type": "SCAN_STARTED", "payload": {"scan_id": "SCAN-2026-000001", "scope_validated": True},
         "created_at": "2026-09-08T10:00:00Z"},
        {"event_type": "SCAN_PHASE", "payload": {"scan_id": "SCAN-2026-000001", "phase": "discovery", "progress": {"network": 40}},
         "created_at": "2026-09-08T10:00:05Z"},
        {"event_type": "SCAN_COMPLETED", "payload": {"scan_id": "SCAN-2026-000001", "phase": "live_monitoring", "progress": {"network": 100}},
         "created_at": "2026-09-08T10:00:10Z"},
        {"event_type": "SCAN_FAILED", "payload": {"scan_id": "SCAN-2026-000002", "reason": "no authorized scope"},
         "created_at": "2026-09-08T10:00:20Z"},
        # unrelated platform event with no scan_id must be ignored
        {"event_type": "auth.login", "payload": {}, "created_at": "2026-09-08T10:00:30Z"},
    ]
    runs = collapse_scan_events(events)
    assert len(runs) == 2
    newest = runs[0]
    assert newest["scan_id"] == "SCAN-2026-000002"
    assert newest["status"] == "failed"
    assert newest["error"] == "no authorized scope"
    completed = runs[1]
    assert completed["scan_id"] == "SCAN-2026-000001"
    assert completed["status"] == "completed"
    assert completed["phase"] == "live_monitoring"
    assert completed["progress"] == {"network": 100}
    assert completed["scope_validated"] is True


def test_collapse_scan_events_ignores_non_scan_and_when_no_scan_id():
    from api.live_scan.orchestrator import collapse_scan_events
    assert collapse_scan_events([]) == []
    assert collapse_scan_events([{"event_type": "telemetry.snapshot", "payload": {}}]) == []
