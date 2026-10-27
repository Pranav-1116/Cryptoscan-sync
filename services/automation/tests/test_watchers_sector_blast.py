"""Deterministic automation: cert watcher, sector activation, blast radius."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from automation.blast_radius import analyze_blast_radius
from automation.sector_activation import (
    activate_sector,
    available_sectors,
    normalize_sector,
)
from automation.watchers.cert_expiry import (
    CertState,
    Severity,
    assess_certificate,
    watch_certificates,
)

NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)


def _cert(days, **kw):
    return {
        "id": f"cert-{days}",
        "not_after": (NOW + timedelta(days=days)).isoformat(),
        "public_key_algorithm": "RSA", "public_key_size": 2048,
        **kw,
    }


# --------------------------------------------------------------- cert watcher
class TestCertWatcher:
    def test_expired_is_critical(self):
        a = assess_certificate(_cert(-3), now=NOW)
        assert a.state == CertState.EXPIRED and a.severity == Severity.CRITICAL
        assert a.alert

    def test_within_7_days_critical(self):
        a = assess_certificate(_cert(5), now=NOW)
        assert a.state == CertState.CRITICAL and a.severity == Severity.CRITICAL

    def test_within_20_days_warn_high(self):
        a = assess_certificate(_cert(15), now=NOW)
        assert a.state == CertState.WARN and a.severity == Severity.HIGH

    def test_valid_no_alert(self):
        a = assess_certificate(_cert(120), now=NOW)
        assert a.state == CertState.OK and a.alert is False

    def test_weak_rsa_key_flagged(self):
        a = assess_certificate(_cert(200, public_key_size=1024), now=NOW)
        assert any("below" in r for r in a.reasons)
        assert a.severity == Severity.CRITICAL

    def test_self_signed_production_flagged(self):
        a = assess_certificate(_cert(200, is_self_signed=True), now=NOW)
        assert any("self-signed" in r for r in a.reasons)

    def test_self_signed_dev_ok(self):
        a = assess_certificate(_cert(200, is_self_signed=True, environment="dev"), now=NOW)
        assert not any("self-signed" in r for r in a.reasons)

    def test_watch_batch_sorts_urgent_first(self):
        report = watch_certificates([_cert(120), _cert(-1), _cert(10), _cert(5)], now=NOW)
        assert report.total == 4 and report.expired == 1
        # expired leads
        assert report.alerts[0]["state"] == CertState.EXPIRED.value

    def test_deterministic(self):
        a = watch_certificates([_cert(5), _cert(150)], now=NOW).as_dict()
        b = watch_certificates([dict(_cert(5)), dict(_cert(150))], now=NOW).as_dict()
        assert a["alerts"] == b["alerts"]


# --------------------------------------------------------------- sector activation
class TestSectorActivation:
    def test_alias_resolution(self):
        assert normalize_sector("Bank") == "banking"
        assert normalize_sector("health care") is None or normalize_sector("healthcare") == "healthcare"

    def test_banking_activates_pci_nist(self):
        act = activate_sector("banking")
        assert "pci_dss" in act.policy_packs
        assert "PCI-DSS" in act.compliance_frameworks
        # sector seeds a banking-specific HSM rule
        assert any("hsm" in r["rule_id"] for r in act.seed_rules)

    def test_unknown_sector_fails_closed(self):
        with pytest.raises(KeyError):
            activate_sector("atlantis")

    def test_seed_rules_are_safe_and_valid(self):
        from automation.rules_engine import AutomationRule

        for sector in ("banking", "healthcare", "energy"):
            act = activate_sector(sector)
            for r in act.seed_rules:
                AutomationRule.from_dict(r)  # raises if invalid

    def test_available_sectors(self):
        ids = {s["sector"] for s in available_sectors()}
        assert {"banking", "healthcare", "energy"} & ids


# --------------------------------------------------------------- blast radius
class TestBlastRadius:
    def test_downstream_tally(self):
        edges = [
            ("hsm-1", "cert-a"), ("hsm-1", "cert-b"),
            ("cert-a", "app-1"), ("cert-b", "app-2"),
            ("app-1", "api-1"), ("app-2", "svc-payments"),
            ("api-1", "svc-payments"),
        ]
        nodes = {
            "hsm-1": {"type": "hsm", "criticality": "MISSION_CRITICAL"},
            "cert-a": {"type": "certificate"}, "cert-b": {"type": "certificate"},
            "app-1": {"type": "application"}, "app-2": {"type": "application"},
            "api-1": {"type": "api"}, "svc-payments": {"type": "business_service"},
        }
        r = analyze_blast_radius("hsm-1", edges, nodes=nodes)
        assert r.reachable == 6
        assert r.as_dict()["impact_layers"]["certificate"] == 2
        assert r.as_dict()["impact_layers"]["application"] == 2
        assert r.as_dict()["impact_layers"]["business_service"] == 1
        assert r.business_services == ["svc-payments"]
        assert r.highest_criticality == "MISSION_CRITICAL"

    def test_deterministic_order(self):
        edges = [("a", "b"), ("a", "c"), ("b", "d")]
        r1 = analyze_blast_radius("a", edges).as_dict()
        r2 = analyze_blast_radius("a", edges).as_dict()
        assert r1["affected"] == r2["affected"]

    def test_no_downstream(self):
        r = analyze_blast_radius("isolated", [])
        assert r.reachable == 0 and r.business_services == []
