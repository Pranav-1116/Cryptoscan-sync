"""Deterministic automation engine tests (no AI/ML)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from automation.engine import build_plan, known_rules_from_dicts
from automation.playbooks import playbook_for_event
from automation.rules_engine import (
    AutomationRule,
    RulesError,
    evaluate_conditions,
    match_event,
)
from automation.safety import ActionTier, classify_action, partition_actions
from automation.scanner_selection import select_scanners
from automation.scheduling import schedule_for_asset

NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)


# --------------------------------------------------------------- scanner selection
class TestScannerSelection:
    def test_cisco_router_selects_network_vendor_protocol_crypto_cert(self):
        r = select_scanners({"id": "r1", "asset_kind": "router", "vendor": "Cisco",
                             "protocols": ["tls"], "exposes_tls": True})
        for s in ("network_scanner", "vendor_scanner", "protocol_scanner",
                  "crypto_scanner", "certificate_scanner"):
            assert s in r.scanners

    def test_ec2_selects_cloud_host_app_crypto_cert(self):
        r = select_scanners({"id": "i1", "asset_kind": "cloud_instance",
                             "cloud_provider": "aws", "platform": "ec2"})
        for s in ("cloud_scanner", "host_scanner", "application_scanner",
                  "crypto_scanner", "certificate_scanner"):
            assert s in r.scanners

    def test_ot_plc_selects_ot_protocol_hardware(self):
        r = select_scanners({"id": "plc1", "asset_kind": "plc",
                             "protocols": ["modbus"]})
        assert "ot_scanner" in r.scanners and "hardware_scanner" in r.scanners
        # an OT asset must never get an active cloud/container scanner
        assert "cloud_scanner" not in r.scanners

    def test_deterministic(self):
        a = {"id": "x", "asset_kind": "host", "vendor": "cisco"}
        assert select_scanners(a).scanners == select_scanners(dict(a)).scanners


# --------------------------------------------------------------- scheduling
class TestScheduling:
    def test_critical_asset_hourly(self):
        s = schedule_for_asset({"id": "c", "criticality": "CRITICAL",
                                "last_scanned_at": (NOW - timedelta(hours=1)).isoformat()}, now=NOW)
        assert s.frequency == "hourly" and s.immediate is False

    def test_low_risk_weekly(self):
        s = schedule_for_asset({"id": "l", "criticality": "LOW",
                                "last_scanned_at": (NOW - timedelta(days=2)).isoformat()}, now=NOW)
        assert s.frequency == "weekly"

    def test_recent_change_triggers_immediate(self):
        s = schedule_for_asset({"id": "r", "criticality": "LOW",
                                "last_scanned_at": (NOW - timedelta(days=5)).isoformat(),
                                "last_changed_at": (NOW - timedelta(hours=1)).isoformat()}, now=NOW)
        assert s.immediate is True and s.frequency == "5m"


# --------------------------------------------------------------- rules engine
class TestRulesEngine:
    def test_rule_validation(self):
        with pytest.raises(RulesError):
            AutomationRule.from_dict({"id": "r", "when": "nope", "then": ["create_alert"]})
        with pytest.raises(RulesError):
            AutomationRule.from_dict({"id": "r", "when": "any", "then": ["teleport"]})
        with pytest.raises(RulesError):
            AutomationRule.from_dict({"id": "r", "when": "any",
                                      "if": [{"field": "x", "operator": "bogus"}],
                                      "then": ["create_alert"]})

    def test_when_if_then_match(self):
        rule = AutomationRule.from_dict({
            "id": "rsa-critical", "name": "RSA critical",
            "when": "crypto_asset_detected",
            "if": [{"field": "algorithm", "operator": "equals", "value": "RSA"},
                   {"field": "criticality", "operator": "equals", "value": "CRITICAL"}],
            "then": ["create_alert", "create_ticket", "add_pqc_queue"],
            "severity": "HIGH",
        })
        event = {"algorithm": "rsa", "criticality": "critical"}
        assert evaluate_conditions(rule, event) is True
        assert evaluate_conditions(rule, {"algorithm": "RSA", "criticality": "LOW"}) is False
        matched = match_event([rule], "crypto_asset_detected", event)
        assert matched and matched[0].actions == ["create_alert", "create_ticket", "add_pqc_queue"]

    def test_numeric_and_in_operators(self):
        rule = AutomationRule.from_dict({
            "id": "cert-soon", "when": "certificate_expiring",
            "if": [{"field": "days_remaining", "operator": "lte", "value": 7}],
            "then": ["create_alert"], "severity": "CRITICAL",
        })
        assert evaluate_conditions(rule, {"days_remaining": 3}) is True
        assert evaluate_conditions(rule, {"days_remaining": 30}) is False

    def test_any_trigger_matches_all(self):
        rule = AutomationRule.from_dict({"id": "all", "when": "any",
                                         "then": ["create_alert"]})
        assert match_event([rule], "anything", {})


# --------------------------------------------------------------- safety
class TestSafety:
    def test_read_actions_auto(self):
        d = classify_action("create_alert")
        assert d.auto_permitted is True and d.tier == ActionTier.RECOMMEND.value

    def test_change_actions_require_approval(self):
        for a in ("apply_remediation", "firmware_update", "disable_asset"):
            d = classify_action(a)
            assert d.requires_approval is True
            assert d.tier in (ActionTier.APPROVE.value, ActionTier.EXECUTE.value)

    def test_unknown_action_fails_closed(self):
        assert classify_action("rm_everything").requires_approval is True

    def test_partition(self):
        p = partition_actions(["create_alert", "firmware_update", "targeted_rescan"])
        assert len(p["auto"]) == 2 and len(p["requires_approval"]) == 1
        assert p["all_safe_without_approval"] is False


# --------------------------------------------------------------- playbooks
class TestPlaybooks:
    def test_pqc_playbook_present_and_gated_at_end(self):
        pb = playbook_for_event("quantum_vulnerable_detected")
        assert pb is not None and "pqc" in pb.id
        gated = pb.gated_steps()
        assert gated, "PQC playbook must have an approval gate"
        # rescan/CBOM steps run automatically
        auto = {s.action for s in pb.auto_steps()}
        assert "targeted_rescan" in auto and "update_cbom" in auto

    def test_certificate_playbook(self):
        pb = playbook_for_event("certificate_expiring")
        assert pb is not None and "certificate" in pb.id


# --------------------------------------------------------------- orchestration
class TestOrchestration:
    def test_plan_auto_and_gated_actions(self):
        rules = known_rules_from_dicts([
            {"id": "rsa-crit", "when": "crypto_asset_detected",
             "if": [{"field": "algorithm", "operator": "equals", "value": "RSA"}],
             "then": ["create_alert", "add_pqc_queue", "create_ticket"], "severity": "HIGH"},
        ])
        event = {"asset_id": "a1", "algorithm": "RSA", "criticality": "CRITICAL"}
        plan = build_plan("crypto_asset_detected", event, rules,
                          select_scanners_for={"id": "a1", "asset_kind": "application",
                                               "exposes_tls": True})
        d = plan.as_dict()
        # PQC playbook includes a request_approval gate
        assert d["needs_human"] is True
        assert any(a["action"] == "create_alert" for a in d["auto_actions"])
        assert any("approval" in a["action"] for a in d["requires_approval"])
        # scanners auto-selected for the application asset
        assert "crypto_scanner" in d["scanners"]
        assert d["matched_rules"][0]["rule_id"] == "rsa-crit"

    def test_plan_deterministic(self):
        rules = known_rules_from_dicts([
            {"id": "r", "when": "any", "then": ["create_alert"]}])
        event = {"asset_id": "z", "asset_kind": "host"}
        a = build_plan("scan_completed", event, rules).as_dict()
        b = build_plan("scan_completed", dict(event), rules).as_dict()
        assert a["auto_actions"] == b["auto_actions"]
        assert a["scanners"] == b["scanners"]
