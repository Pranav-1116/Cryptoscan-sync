"""Risk dimensions — roadmap item 7 acceptance rows.

Standing directive: "Every score should be explainable and reproducible." Also:
the five dimensions stay separate, blending is opt-in and transparent, and "I do
not know this value" is never scored as "this value is fine".
"""

from __future__ import annotations

import json

from shared_models.algorithm_registry import parse_algorithm
from shared_models.risk_dimensions import (
    CRYPTO_RISK,
    EVIDENCE_CONFIDENCE,
    OPERATIONAL_DEPENDENCY,
    QUANTUM_URGENCY,
    RISK_RULES_VERSION,
    VENDOR_RISK,
    risk_profile,
    score_crypto_risk,
    score_evidence_confidence,
    score_operational_dependency,
    score_quantum_urgency,
    score_vendor_risk,
)


class TestExplainableAndReproducible:

    def test_every_score_carries_its_rules_and_evidence(self):
        result = score_crypto_risk(
            algorithm_info=parse_algorithm("RSA-2048"),
            usage_state="NEGOTIATED", evidence_ids=["E1"])
        assert result["known"] is True
        assert result["rules_version"] == RISK_RULES_VERSION
        for factor in result["factors"]:
            assert set(factor) == {"rule", "input", "contribution", "evidence_ids"}
        assert result["evidence_ids"] == ["E1"]

    def test_the_same_inputs_produce_byte_identical_reports(self):
        kwargs = dict(algorithm_info=parse_algorithm("AES-128"),
                      usage_state="CONFIGURED", evidence_ids=["E2"])
        first = json.dumps(score_crypto_risk(**kwargs), sort_keys=True)
        second = json.dumps(score_crypto_risk(**kwargs), sort_keys=True)
        assert first == second

    def test_the_registry_facts_feed_the_rules(self):
        # RSA-1024: DISALLOWED, Shor-broken, key below family minimum, live use
        result = score_crypto_risk(algorithm_info=parse_algorithm("RSA-1024"),
                                   usage_state="NEGOTIATED")
        rules = {f["rule"]: f["contribution"] for f in result["factors"]}
        assert rules["CR-1"] == 50        # DISALLOWED
        assert rules["CR-2"] == 30        # Shor
        assert rules["CR-3"] == 25        # 1024 < 2048 minimum
        assert rules["CR-4"] == 10        # live use
        assert result["score"] == 100     # 115 capped
        assert result["band"] == "CRITICAL"

    def test_an_allowed_but_shor_broken_algorithm_is_scored_not_ignored(self):
        result = score_crypto_risk(algorithm_info=parse_algorithm("RSA-2048"),
                                   usage_state="NEGOTIATED")
        rules = {f["rule"]: f["contribution"] for f in result["factors"]}
        assert rules["CR-1"] == 0         # ALLOWED at 2048 bits
        assert rules["CR-2"] == 30        # but Shor-broken
        assert result["score"] == 40

    def test_capability_scores_less_than_usage(self):
        capability = score_crypto_risk(algorithm_info=parse_algorithm("AES-256"),
                                       usage_state="SUPPORTED")
        live = score_crypto_risk(algorithm_info=parse_algorithm("AES-256"),
                                 usage_state="OBSERVED")
        assert capability["score"] < live["score"]


class TestUnknownIsNeverZero:

    def test_an_unrecognised_algorithm_is_unscoreable_not_safe(self):
        result = score_crypto_risk(algorithm_info=parse_algorithm("NOT-A-CIPHER"))
        assert result["score"] is None
        assert result["band"] == "UNKNOWN"
        assert result["known"] is False
        assert "not a low-risk algorithm" in result["reason"]

    def test_quantum_urgency_refuses_without_an_explicit_threat_horizon(self):
        result = score_quantum_urgency(
            algorithm_info=parse_algorithm("RSA-2048"),
            quantum_threat_horizon_years=None)
        assert result["score"] is None
        assert "policy input" in result["reason"]

    def test_quantum_urgency_dates_exposure_window_arithmetic(self):
        result = score_quantum_urgency(
            algorithm_info=parse_algorithm("RSA-2048"),
            usage_state="NEGOTIATED",
            data_shelf_life_years=7, migration_lead_time_years=3,
            quantum_threat_horizon_years=5)
        rules = {f["rule"]: f["contribution"] for f in result["factors"]}
        assert rules["QU-1"] == 40                       # Shor
        assert rules["QU-2"] == 20                       # exposure 7+3-5 = 5y → 1–10y band
        assert rules["QU-3"] == 15

    def test_no_evidence_is_never_full_confidence(self):
        result = score_evidence_confidence(records=[])
        assert result["score"] is None
        assert result["sense"] == "confidence"
        assert "never full confidence" in result["reason"]

    def test_no_vendor_is_unknown_vendor_risk(self):
        result = score_vendor_risk(vendor=None)
        assert result["score"] is None
        assert "never zero" in result["reason"]

    def test_unknown_support_state_is_not_good_support(self):
        result = score_vendor_risk(vendor="acme", support_state=None)
        assert result["score"] is None
        assert "unknown support is not good support" in result["reason"]


class TestOperationalDependency:

    def test_proven_chains_weigh_more_than_inferred_and_unknown(self):
        proven = score_operational_dependency(dependents=2, proven_chains=3)
        inferred = score_operational_dependency(dependents=2, inferred_chains=3)
        unknown = score_operational_dependency(dependents=2, unknown_chains=3)
        assert proven["score"] > inferred["score"] > unknown["score"]

    def test_an_unmeasured_blast_radius_still_adds_caution(self):
        zero = score_operational_dependency(dependents=2)
        unknown = score_operational_dependency(dependents=2, unknown_chains=2)
        assert unknown["score"] > zero["score"]
        factor = next(f for f in unknown["factors"] if f["rule"] == "OD-4")
        assert factor["contribution"] > 0


class TestRiskProfile:

    def _five(self):
        return {
            "crypto_risk": score_crypto_risk(algorithm_info=parse_algorithm("RSA-2048"),
                                             usage_state="OBSERVED"),
            "quantum_urgency": score_quantum_urgency(
                algorithm_info=parse_algorithm("RSA-2048"),
                quantum_threat_horizon_years=5),
            "operational_dependency": score_operational_dependency(dependents=3),
            "evidence_confidence": score_evidence_confidence(
                records=[{"evidence_type": "RUNTIME_OBSERVED", "confidence": "HIGH",
                          "observed_at": "2026-11-07T00:00:00+00:00",
                          "evidence_id": "E1"}]),
            "vendor_risk": score_vendor_risk(vendor="acme", support_state="EOL",
                                             eol_announced=True),
        }

    def test_the_five_dimensions_stay_separate_by_default(self):
        profile = risk_profile(**self._five())
        assert set(profile["dimensions"]) == {
            CRYPTO_RISK, QUANTUM_URGENCY, OPERATIONAL_DEPENDENCY,
            EVIDENCE_CONFIDENCE, VENDOR_RISK}
        assert profile["blended_score"] is None
        assert profile["blended_requested"] is False
        assert "never replaces the dimensions" in profile["note"]

    def test_blending_is_opt_in_and_shows_its_arithmetic(self):
        profile = risk_profile(**self._five(), blended=True)
        assert profile["blended_requested"] is True
        assert isinstance(profile["blended_score"], float)
        # only risk-sense dimensions are averaged; evidence confidence is not risk
        assert EVIDENCE_CONFIDENCE not in profile["blended_arithmetic"][0]
        assert len(profile["blended_arithmetic"]) == 4
        for row in profile["blended_arithmetic"]:
            assert "=" in row

    def test_a_missing_dimension_is_excluded_from_blends_never_averaged_as_zero(self):
        five = self._five()
        del five["vendor_risk"]
        profile = risk_profile(**five, blended=True)
        assert profile["dimensions"][VENDOR_RISK]["score"] is None
        assert VENDOR_RISK in profile["excluded_dimensions"]
        assert VENDOR_RISK not in " ".join(profile["blended_arithmetic"])

    def test_evidence_confidence_is_the_one_dimension_where_high_is_good(self):
        profile = risk_profile(**self._five())
        assert profile["dimensions"][EVIDENCE_CONFIDENCE]["sense"] == "confidence"
        assert profile["dimensions"][CRYPTO_RISK]["sense"] == "risk"
