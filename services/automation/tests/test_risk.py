"""Deterministic risk recalculation / up-chain propagation tests (no AI/ML)."""

from __future__ import annotations

from automation.risk import base_risk, recalculate, risk_band


class TestBaseRisk:
    def test_no_findings_is_none(self):
        assert base_risk({}) == 0 and risk_band(0) == "NONE"

    def test_critical_findings_score_high(self):
        s = base_risk({"findings": [{"severity": "CRITICAL"}], "criticality": "HIGH"})
        assert s > 0 and risk_band(s) in ("MEDIUM", "HIGH", "CRITICAL")
        # multiple critical findings on a mission-critical asset reach CRITICAL band
        s2 = base_risk({"findings": [{"severity": "CRITICAL"}] * 4,
                        "criticality": "MISSION_CRITICAL"})
        assert risk_band(s2) == "CRITICAL"

    def test_quantum_vulnerable_adds_weight(self):
        plain = base_risk({"criticality": "MEDIUM"})
        quantum = base_risk({"criticality": "MEDIUM", "quantum_vulnerable": True})
        assert quantum > plain

    def test_criticality_multiplier(self):
        low = base_risk({"findings": [{"severity": "HIGH"}], "criticality": "LOW"})
        crit = base_risk({"findings": [{"severity": "HIGH"}], "criticality": "MISSION_CRITICAL"})
        assert crit > low


class TestPropagation:
    def test_library_risk_propagates_to_service(self):
        # business_service -> app -> library (caller -> callee edges)
        assets = {
            "svc": {"type": "business_service", "criticality": "MEDIUM", "name": "Payments"},
            "app": {"type": "application", "criticality": "HIGH"},
            "lib": {"type": "library", "criticality": "LOW",
                    "findings": [{"severity": "CRITICAL"}], "weak_key": True},
        }
        edges = [("svc", "app"), ("app", "lib")]
        result = recalculate(assets, edges, changed_assets=["lib"])
        # lib high, app inherits 0.8*lib, svc inherits 0.8*app
        assert result.scores["lib"] > 0
        assert result.scores["app"] <= result.scores["lib"]
        assert result.scores["svc"] <= result.scores["app"]
        assert "app" in result.changed and "svc" in result.changed
        assert "Payments" in result.affected_business_services

    def test_new_library_risk_lifts_business_service(self):
        assets = {
            "svc": {"type": "business_service", "name": "Checkout"},
            "svc2": {"type": "business_service", "name": "Unrelated"},
            "app": {"type": "application"},
            "lib": {"type": "library", "quantum_vulnerable": True,
                    "findings": [{"severity": "HIGH"}, {"severity": "HIGH"}]},
        }
        edges = [("svc", "app"), ("app", "lib")]
        result = recalculate(assets, edges, changed_assets=["lib"])
        assert "Checkout" in result.affected_business_services
        assert "Unrelated" not in result.affected_business_services

    def test_deterministic(self):
        assets = {"svc": {"type": "business_service", "name": "S"},
                  "lib": {"findings": [{"severity": "CRITICAL"}]}}
        edges = [("svc", "lib")]
        a = recalculate(assets, edges).as_dict()
        b = recalculate(dict(assets), edges).as_dict()
        assert a["scores"] == b["scores"]
