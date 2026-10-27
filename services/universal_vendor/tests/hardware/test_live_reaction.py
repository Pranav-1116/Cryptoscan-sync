"""Change-triggered targeted re-discovery (§6) — the most important
optimization: EVENT → WHAT CHANGED → WHICH HARDWARE → WHAT INFORMATION →
RUN ONLY REQUIRED DISCOVERY."""

from __future__ import annotations

from universal_vendor.hardware.live import ChangeReactionPlanner


def test_bios_update_targeted_plan_spec_example():
    """§6 example: BIOS updated → BIOS verification → hardware capability
    verification → crypto capability verification → PQC reassessment."""
    planner = ChangeReactionPlanner()
    plan = planner.plan(event_type="BIOS_CHANGED", asset_id="srv-1")
    assert plan["scope"] == "TARGETED"
    actions = plan["required_actions"]
    assert "bios_verification" in actions
    assert "hardware_capability_verification" in actions
    assert "crypto_capability_verification" in actions
    assert "pqc_reassessment" in actions
    # the whole point: unrelated subsystems are explicitly excluded
    assert "storage re-scan" in plan["explicitly_not_affected"]
    assert "network re-scan" in plan["explicitly_not_affected"]


def test_nic_change_targets_network_not_storage():
    planner = ChangeReactionPlanner()
    plan = planner.plan(event_type="NIC_CHANGED", asset_id="srv-1")
    assert "nic_verification" in plan["required_actions"]
    assert "network_relationship_analysis" in plan["required_actions"]
    assert "storage re-scan" in plan["explicitly_not_affected"]
    assert "BIOS re-verification" in plan["explicitly_not_affected"]


def test_storage_change_does_not_rescan_network():
    planner = ChangeReactionPlanner()
    plan = planner.plan(event_type="STORAGE_CHANGED", asset_id="srv-1")
    assert "storage_verification" in plan["required_actions"]
    assert "network re-scan" in plan["explicitly_not_affected"]


def test_tpm_change_triggers_crypto_and_pqc():
    planner = ChangeReactionPlanner()
    plan = planner.plan(event_type="TPM_UNAVAILABLE", asset_id="srv-1")
    assert "tpm_verification" in plan["required_actions"]
    assert "security_drift_check" in plan["required_actions"]
    assert "crypto_capability_verification" in plan["required_actions"]


def test_hsm_change_triggers_crypto_and_pqc():
    planner = ChangeReactionPlanner()
    plan = planner.plan(event_type="HSM_CHANGED", asset_id="hsm-1")
    assert "hsm_verification" in plan["required_actions"]
    assert "pqc_reassessment" in plan["required_actions"]


def test_removal_never_reverifies_capabilities():
    planner = ChangeReactionPlanner()
    plan = planner.plan(event_type="HARDWARE_REMOVED", asset_id="srv-1")
    assert "confirm_removal" in plan["required_actions"]
    assert "capability re-verification" in plan["explicitly_not_affected"]


def test_legacy_event_alias_plans():
    planner = ChangeReactionPlanner()
    plan = planner.plan(event_type="DEVICE_ADDED", asset_id="srv-1")
    assert plan["event_type"] == "HARDWARE_DISCOVERED"
    assert "full_inventory" in plan["required_actions"]
