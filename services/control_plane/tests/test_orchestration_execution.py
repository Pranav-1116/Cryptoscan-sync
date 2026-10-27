"""Tests for the executing layer: orchestrator dispatch, observability, vault."""

from datetime import datetime, timezone

from control_plane import (
    Orchestrator,
    OrchestratorConfig,
    emergency_engaged,
    fleet_health,
    get_adapter,
    lease_credential,
    overall_status,
    queue_health,
    scanner_for_event,
)
from control_plane.vault import VaultError


class FakeRepo:
    def __init__(self, events):
        self._events = events

    def list_events(self, status=None, limit=100):
        if status:
            return [e for e in self._events if e.get("status") == status]
        return list(self._events)


NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


def _ev(id_, type_, priority="normal", status="queued", payload=None, created=None):
    return {"id": id_, "event_type": type_, "priority": priority, "status": status,
            "payload": payload or {}, "created_at": (created or "2026-09-06T10:00:00+00:00"),
            "attempts": 0, "max_attempts": 5, "available_at": "2026-09-06T09:00:00+00:00"}


# --------------------------------------------------------------- orchestrator
def test_dispatches_highest_priority_first():
    repo = FakeRepo([_ev("1", "scan.start", "normal"), _ev("2", "scan.start", "critical")])
    orch = Orchestrator(repo, OrchestratorConfig(worker_id="w1"))
    # FakeRepo returns dicts; leasing mutates state via repo in real impl, here
    # we just validate selection through the dispatch decision.
    result = orch.dispatch_next(now=NOW)
    assert result.permitted is True
    # critical event id 2 sorts first (created equal; priority critical)
    assert result.leased_id == "2"


def test_emergency_stop_blocks_dispatch():
    events = [
        _ev("s1", "safe_scan.emergency_stop", "critical", status="completed",
            payload={"engaged": True}, created="2026-09-06T11:00:00+00:00"),
        _ev("1", "scan.start", "critical"),
    ]
    orch = Orchestrator(FakeRepo(events), OrchestratorConfig())
    res = orch.dispatch_next(now=NOW)
    assert res.permitted is False and "emergency" in res.reason


def test_emergency_disengage_allows_dispatch():
    events = [
        _ev("s1", "safe_scan.emergency_stop", payload={"engaged": True}, created="2026-09-06T11:00:00+00:00", status="completed"),
        _ev("s2", "safe_scan.emergency_stop", payload={"engaged": False}, created="2026-09-06T11:30:00+00:00", status="completed"),
        _ev("1", "scan.start", "critical"),
    ]
    assert emergency_engaged(events) is False


def test_concurrency_cap():
    repo = FakeRepo([_ev("1", "scan.start")])
    orch = Orchestrator(repo, OrchestratorConfig(max_concurrency=1))
    orch.active_leases.add("x")
    res = orch.dispatch_next(now=NOW)
    assert res.permitted is False and "concurrency" in res.reason


def test_safe_policy_blocks_ot_scan_via_policy_provider():
    repo = FakeRepo([_ev("1", "scan.start", payload={"is_ot": True, "port": 22})])
    policy = {"mode": "standard", "excluded_ports": [22]}
    orch = Orchestrator(repo, OrchestratorConfig(),
                        policy_provider=lambda p: policy)
    res = orch.dispatch_next(now=NOW)
    assert res.permitted is False


def test_cancelled_event_not_leased():
    repo = FakeRepo([_ev("1", "scan.start")])
    orch = Orchestrator(repo, OrchestratorConfig())
    orch.cancel("1")
    res = orch.dispatch_next(now=NOW)
    assert res.cancelled is True


def test_scanner_selection_by_domain():
    assert scanner_for_event("scan.start", {"domain": "cloud"}) == "cloud_scanner"
    assert scanner_for_event("scan.start", {"domain": "network"}) == "network_scanner"
    assert scanner_for_event("scan.start", {"kind": "hsm"}) == "ot_scanner"
    assert scanner_for_event("scan.vendor", {}) == "universal_vendor"


# --------------------------------------------------------------- observability
def test_fleet_health_detects_stale():
    agents = [
        {"status": "connected", "last_heartbeat_at": NOW.isoformat(), "version": "1.0"},
        {"status": "connected", "last_heartbeat_at": "2020-01-01T00:00:00+00:00", "version": "1.0"},
        {"status": "enrolled", "version": "0.9"},
    ]
    fh = fleet_health(agents, now=NOW, stale_after_seconds=300)
    assert fh["connected"] == 1 and fh["stale"] == 1 and fh["total"] == 3
    assert fh["versions"]["1.0"] == 2


def test_queue_health_dead_rate():
    events = [{"status": "queued"} for _ in range(8)] + [{"status": "dead"} for _ in range(2)]
    qh = queue_health(events)
    assert qh["dead"] == 2 and qh["dead_letter_rate"] == 0.2 and qh["healthy"] is False


def test_overall_status_rolls_up():
    st = overall_status(queue=queue_health([]), fleet=fleet_health([]),
                        credentials={"healthy": True}, api_up=True, db_up=True)
    assert st["status"] == "ok"
    st2 = overall_status(queue={"healthy": False}, fleet={"healthy": True},
                         credentials={"healthy": True}, api_up=True, db_up=True)
    assert st2["status"] == "degraded"
    st3 = overall_status(queue={"healthy": True}, fleet={"healthy": True},
                         credentials={"healthy": True}, api_up=False, db_up=True)
    assert st3["status"] == "critical"


# --------------------------------------------------------------------- vault
def test_vault_adapter_selection():
    assert get_adapter("aws_secrets_manager").name == "aws_secrets_manager"
    assert get_adapter("manual_out_of_band").name == "manual_out_of_band"
    try:
        get_adapter("nope")
        assert False
    except VaultError:
        pass


def test_lease_out_of_band_without_value(monkeypatch):
    monkeypatch.delenv("ZELNX_CRED_VAULT_X", raising=False)
    cred = {"vault_provider": "manual_out_of_band", "secret_ref": "x",
            "status": "active", "kind": "cloud"}
    lease = lease_credential(cred, require_value=False)
    assert lease.value is None and lease.read_only is True
    assert lease.redacted()["value"] == "<redacted>"


def test_lease_revoked_fails_closed():
    try:
        lease_credential({"vault_provider": "manual_out_of_band", "secret_ref": "x",
                          "status": "revoked", "kind": "cloud"})
        assert False
    except VaultError:
        pass
