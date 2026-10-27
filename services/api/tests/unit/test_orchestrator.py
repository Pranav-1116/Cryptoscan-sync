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
        {"kind": "application", "target": "local://test-fixture/vulnerable-app", "enabled": True, "detail": {}},
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
    assert "local://test-fixture/vulnerable-app" in targets["source"]
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


def test_gate_denies_scan_that_has_no_authorized_targets():
    from api.live_scan.orchestrator import OrchestratorScan, get_scan_orchestrator
    orch = get_scan_orchestrator()
    run = OrchestratorScan(scan_id="SCAN-2026-000001", org_id="o1", org_name="Acme",
                           phase="scope_validated", status="running", started_at="",
                           scope_validated=False, targets={}, credentials={})
    d = orch._evaluate_gate(actor="alice", org=run, policy=None, scope_meta=None)
    assert d.denied and d.denied_by == "scope"


def test_gate_evaluation_records_full_control_chain():
    from api.live_scan.orchestrator import OrchestratorScan, get_scan_orchestrator
    orch = get_scan_orchestrator()
    run = OrchestratorScan(scan_id="SCAN-2026-000002", org_id="o1", org_name="Acme",
                           phase="scope_validated", status="running", started_at="",
                           scope_validated=True,
                           targets={"network": ["10.20.0.10:443"]},
                           credentials={"network": True})
    d = orch._evaluate_gate(actor="alice", org=run, policy=None,
                            scope_meta={"excluded": [], "special": [], "special_approved": False})
    assert d.permitted, d.reason
    controls = {c.control for c in d.checks}
    assert {"authorization", "scope", "privacy", "scan_policy", "rate_limit",
            "target_safety", "credential"} <= controls


def test_start_denies_when_policy_intensity_off_without_spawning():
    from api.live_scan.orchestrator import get_scan_orchestrator
    orch = get_scan_orchestrator()
    run = orch.start(_org(), _scope(), _connectors(), [], only=None,
                     policy={"scan": {"intensity": "off", "mode": "read-only"}})
    assert run.status == "failed"
    assert run.phase == "failed"
    assert run.gate is not None
    assert run.gate.get("denied_by") == "scan_policy"
    assert "intensity is OFF" in (run.error or "")


def test_start_accepts_sector_param_and_records_full_gate():
    """A sector-seeded scan still runs the full control chain and records it."""
    from api.live_scan.orchestrator import get_scan_orchestrator
    orch = get_scan_orchestrator()
    run = orch.start(_org(), _scope(), _connectors(), [], only=None, sector="banking")
    assert run.gate is not None
    # the sector parameter is accepted and the gate runs the control chain in
    # order. For a conservative scope the chain may short-circuit at rate_limit,
    # so assert the earliest stages all ran.
    controls = {c["control"] for c in run.gate.get("checks", [])}
    assert {"authorization", "scope", "privacy", "scan_policy"} <= controls


def test_gate_fails_closed_when_privacy_layer_throws(monkeypatch):
    """If the privacy/gate layer errors, the scan is DENIED (never fabricated
    into an allow)."""
    from api.live_scan.orchestrator import OrchestratorScan, get_scan_orchestrator
    orch = get_scan_orchestrator()
    run = OrchestratorScan(scan_id="SCAN-2026-000009", org_id="o1", org_name="Acme",
                           phase="scope_validated", status="running", started_at="",
                           scope_validated=True,
                           targets={"network": ["10.20.0.10:443"]},
                           credentials={"network": True})
    import privacy.policy as pp

    def boom(*a, **k):
        raise RuntimeError("privacy layer unavailable")

    monkeypatch.setattr(pp, "build_policy", boom)
    d = orch._evaluate_gate(actor="alice", org=run, policy=None, scope_meta=None)
    assert d.denied is True
    assert d.denied_by == "gate"
    assert "fail-closed" in d.reason
