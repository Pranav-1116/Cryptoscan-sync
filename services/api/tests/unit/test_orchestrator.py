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


def test_scan_id_format_constant():
    from api.live_scan.orchestrator import SCAN_ID_FORMAT
    assert "{" in SCAN_ID_FORMAT       # format template, e.g. SCAN-2026-000001
    assert SCAN_ID_FORMAT.startswith("SCAN-")
