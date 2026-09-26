"""LiveHardwareController — the LIVE HARDWARE ENGINE end to end.

Event → identity → classification → impact → targeted scan plan → state →
evidence chain → versioned HBOM → timeline → drift → risk recalc →
correlated alert → PQC impact. Plus heartbeats (§4) and the §6 BIOS
update scenario.
"""

from __future__ import annotations

from universal_vendor.hardware.live import (
    HardwareEvent,
    HardwareEventType,
    HardwarePqcImpactEngine,
    LiveHardwareController,
)
from universal_vendor.hardware.live.state import HardwareDriftEngine


def _event(etype, asset="srv-1", **kw):
    return HardwareEvent(event_type=etype, asset_id=asset, **kw)


def test_controller_ingest_discovery_pipeline():
    ctl = LiveHardwareController()
    result = ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED,
                               manufacturer="Dell", model="R760",
                               device_type="server"))
    assert result["state_verdict"] == "NEW"
    assert result["envelope"]["change_class"] == "NEW_DISCOVERY"
    assert result["targeted_plan"]["scope"] == "TARGETED"
    assert "full_inventory" in result["targeted_plan"]["required_actions"]
    assert result["hbom_version"] == 2  # v1 baseline + snapshot v2
    assert result["evidence_id"]
    assert result["incident"]["root_asset_id"] == "srv-1"
    # risk was calculated on discovery
    assert result["risk"]["asset_id"] == "srv-1"
    assert result["risk"]["score"] > 0
    # evidence chain verifies
    assert ctl.evidence_valid() is True


def test_controller_bios_update_scenario():
    """§6 example end to end: BIOS updated → BIOS verification → capability
    verification → crypto capability verification → PQC reassessment."""
    ctl = LiveHardwareController()
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED,
                      manufacturer="Dell", model="R760"))
    result = ctl.ingest(_event(HardwareEventType.BIOS_CHANGED,
                               component="BIOS", version="2.19"))
    actions = result["targeted_plan"]["required_actions"]
    assert "bios_verification" in actions
    assert "hardware_capability_verification" in actions
    assert "crypto_capability_verification" in actions
    assert "pqc_reassessment" in actions
    assert result["pqc_assessment"] is not None  # §18 automatic trigger
    # state reflects new firmware; previous state preserved
    live = ctl.live_state("srv-1")[0]
    assert live["firmware"]["BIOS"] == "2.19"
    assert live["previous_state"]["firmware"] == {}
    assert live["last_firmware_check"] is not None
    # timeline recorded both events
    assert len(ctl.timeline("srv-1")) == 2
    # HBOM versioning: snapshot(1) at discovery, snapshot(2) at BIOS change
    assert len(ctl.hbom_versions()) == 2
    assert ctl.hbom_versions()[-1]["version"] == 2
    assert "BIOS_CHANGED" in ctl.hbom_versions()[-1]["reason"]
    assert ctl.hbom_versions()[0]["version"] == 1


def test_controller_state_at_reconstructs_history():
    ctl = LiveHardwareController()
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED,
                      manufacturer="Dell", model="R760"))
    ctl.ingest(_event(HardwareEventType.BIOS_CHANGED, component="BIOS",
                      version="2.18"))
    ctl.ingest(_event(HardwareEventType.TPM_AVAILABLE,
                      tpm={"present": True, "version": "2.0"}))
    before = ctl.state_at("srv-1", ctl.timeline("srv-1")[1]["timestamp"])
    assert before["tpm"] is None
    after = ctl.state_at("srv-1", ctl.timeline("srv-1")[2]["timestamp"])
    assert after["tpm"]["present"] is True


def test_controller_removal_and_repeat_removal():
    ctl = LiveHardwareController()
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED))
    r1 = ctl.ingest(_event(HardwareEventType.HARDWARE_REMOVED))
    assert r1["state_verdict"] == "REMOVED"
    r2 = ctl.ingest(_event(HardwareEventType.HARDWARE_REMOVED))
    assert r2["state_verdict"] == "NO_CHANGE"


def test_controller_heartbeat_and_agent_loss_never_removes_hardware():
    ctl = LiveHardwareController()
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED, agent_id="edge-1"))
    ctl.ingest_heartbeat(agent_id="edge-1", hardware_count=1)
    assert ctl.agent_health("edge-1")[0]["agent_status"] == "ONLINE"

    # simulate heartbeat loss: evaluate with a far-future clock
    from datetime import datetime, timedelta, timezone

    future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    alerts = ctl.evaluate_agents(now=future)
    assert any(a["alert_type"] == "AGENT_UNAVAILABLE" for a in alerts)
    # the hardware is still in the live state — nothing was removed
    assert len(ctl.live_state()) == 1
    assert ctl.live_state("srv-1")[0]["agent_id"] == "edge-1"


def test_controller_drift_evaluation():
    ctl = LiveHardwareController(drift=HardwareDriftEngine())
    ctl.drift.set_expected("srv-1", {"tpm": {"present": True, "version": "2.0"},
                                     "firmware": {"BIOS": "2.18"}})
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED,
                      manufacturer="Dell", model="R760"))
    result = ctl.ingest(_event(HardwareEventType.TPM_UNAVAILABLE,
                               tpm={"present": False}))
    assert result["drift"] is not None
    assert result["drift"]["state"] == "SECURITY_HARDWARE_DRIFT"


def test_controller_crypto_capability_change_triggers_pqc_and_risk_recalc():
    from universal_vendor.hardware.correlation import HardwareCorrelationEngine

    correlation = HardwareCorrelationEngine()
    for i in range(12):  # 12 applications depend on this HSM (§18 example)
        correlation.link_hardware_to_software(
            server="srv-1", component="hsm", operating_system=f"os-{i}",
            crypto_library="pkcs11", application=f"app-{i}", certificate=f"cert-{i}",
        )
    ctl = LiveHardwareController(pqc=HardwarePqcImpactEngine(correlation=correlation))
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED,
                      manufacturer="Thales", model="Luna"))
    ctl.risk_score("srv-1")
    result = ctl.ingest(_event(HardwareEventType.CRYPTO_CAPABILITY_CHANGED,
                               crypto_capabilities={"pqc_hybrid": False}))
    assert result["pqc_assessment"]["migration_impact"] == "HIGH"  # §18 example
    assert result["pqc_assessment"]["affected_application_count"] >= 12
    after = ctl.risk_score("srv-1")
    assert after is not None
    assert result["state_verdict"] == "CHANGED"


def test_controller_evidence_chain_tamper_detection():
    ctl = LiveHardwareController()
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED))
    ctl.ingest(_event(HardwareEventType.BIOS_CHANGED, component="BIOS", version="2.18"))
    assert ctl.evidence_valid() is True
    # tamper with the first evidence record
    ctl._evidence[0]["observation"]["asset_id"] = "attacker-controlled"
    assert ctl.evidence_valid() is False


def test_controller_incident_correlation_one_root():
    ctl = LiveHardwareController()
    ctl.ingest(_event(HardwareEventType.HARDWARE_DISCOVERED))
    ctl.ingest(_event(HardwareEventType.BIOS_CHANGED, component="BIOS", version="2.18"))
    ctl.ingest(_event(HardwareEventType.BMC_CHANGED, component="BMC", version="1.2"))
    incidents = ctl.incidents()
    assert len(incidents) == 2  # discovery root + ONE change root (§20)
    change_incident = next(i for i in incidents if i["root_type"] == "HARDWARE_CHANGE")
    assert change_incident["child_event_count"] == 2  # BIOS + BMC collapsed
    assert "BIOS_CHANGED" in change_incident["child_types"]
