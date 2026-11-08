"""OS & Kernel risk model (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md §9 "Risk calculation").

R = f(S,E,X,B,C) — S security significance, E evidence confidence, X
actual exposure, B business impact, C compensating controls.

The output is a COMPUTED severity label plus the preserved factors and
a written derivation. It is NOT a multiplied number presented as a
scientifically validated score — the factors and the model version
travel with every assessment so a bank can review the decision.
Severity is computed by the documented ladder below; it is never named
by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

RISK_MODEL_VERSION = "os-risk/1.0"

#: S — security significance of the detected condition itself.
SECURITY_SIGNIFICANCE = ("low", "medium", "high")

#: E — evidence confidence, DERIVED from the evidence classification
#: (§5 taxonomy). Never a hand-picked number.
_EVIDENCE_CONFIDENCE = {
    "observed": "high",
    "strongly_supported": "high",
    "indicated": "medium",
    "inferred": "low",
    "unknown": "none",
    "not_detected": "none",
}

#: X — actual exposure. "observed" requires runtime-confirmed use;
#: read-only OS collection never produces it (§2.2).
EXPOSURE = ("not_established", "configuration_only", "observed")

#: B — business impact. The platform does NOT invent business impact:
#: without a registered business mapping the factor stays
#: "requires_registered_mapping".
BUSINESS_IMPACT = ("requires_registered_mapping", "registered_low",
                   "registered_medium", "registered_high")

#: C — compensating controls.
COMPENSATING = ("unknown", "recorded")

SEVERITY_LABELS = ("informational", "low", "medium", "high", "critical")


@dataclass
class RiskAssessment:
    severity_label: str
    model_version: str
    factors: Dict[str, str]
    derivation: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "severity_label": self.severity_label,
            "risk_model_version": self.model_version,
            "factors": self.factors,
            "derivation": self.derivation,
            "note": "computed by the documented ladder of "
                    f"{self.model_version} — the factors are preserved "
                    "for review; this is not a multiplied 'scientifically "
                    "validated score' (§9)",
        }


def assess(*, security_significance: str,
           evidence_class: str,
           exposure: str = "not_established",
           business_impact: str = "requires_registered_mapping",
           compensating_controls: str = "unknown") -> RiskAssessment:
    """Compute severity with the documented ladder. Every input is
    validated; an invalid factor is refused, never guessed."""
    if security_significance not in SECURITY_SIGNIFICANCE:
        raise ValueError(f"security_significance must be one of "
                         f"{SECURITY_SIGNIFICANCE}, got "
                         f"{security_significance!r}")
    if exposure not in EXPOSURE:
        raise ValueError(f"exposure must be one of {EXPOSURE}, got "
                         f"{exposure!r}")
    if business_impact not in BUSINESS_IMPACT:
        raise ValueError(f"business_impact must be one of "
                         f"{BUSINESS_IMPACT}, got {business_impact!r}")
    if compensating_controls not in COMPENSATING:
        raise ValueError(f"compensating_controls must be one of "
                         f"{COMPENSATING}, got {compensating_controls!r}")
    evidence_confidence = _EVIDENCE_CONFIDENCE.get(evidence_class, "none")

    factors = {
        "S_security_significance": security_significance,
        "E_evidence_confidence": f"{evidence_confidence} (from evidence "
                                 f"class {evidence_class!r})",
        "X_actual_exposure": exposure,
        "B_business_impact": business_impact,
        "C_compensating_controls": compensating_controls,
    }

    ladder: List[str] = []
    rank = {"informational": 0, "low": 1, "medium": 2, "high": 3,
            "critical": 4}
    reverse = {v: k for k, v in rank.items()}

    # base from S
    level = {"low": 1, "medium": 2, "high": 3}[security_significance]
    ladder.append(f"base = {reverse[level]} from S={security_significance!r}")

    # E: no evidence → informational ceiling is wrong; drop to low cap
    if evidence_confidence == "none":
        level = min(level, 1)
        ladder.append("E=none: severity capped at 'low' — a condition "
                      "with no evidence confidence is never raised")
    elif evidence_confidence == "low":
        level = min(level, 2)
        ladder.append("E=low: severity capped at 'medium'")

    # X: exposure never established → one level down
    if exposure == "not_established":
        level = max(level - 1, 0)
        ladder.append("X=not_established: one level down — a detection "
                      "without established exposure is never presented "
                      "at its full significance")
    elif exposure == "observed":
        ladder.append("X=observed: exposure established by runtime "
                      "evidence (never produced by read-only OS "
                      "collection alone, §2.2)")

    # B: without a registered business mapping, 'high' is unreachable
    if business_impact == "requires_registered_mapping":
        level = min(level, 2)
        ladder.append("B=requires_registered_mapping: severity capped "
                      "at 'medium' — business impact is never invented")
    elif business_impact == "registered_high" and exposure == "observed":
        if security_significance == "high":
            level = min(level + 1, 4)
            ladder.append("B=registered_high with X=observed and "
                          "S=high: one level up — the only documented "
                          "path toward 'critical'")
        else:
            ladder.append("B=registered_high with X=observed: exposure "
                          "and business impact established; 'critical' "
                          "still requires S=high")

    # C: recorded compensating controls → one level down
    if compensating_controls == "recorded":
        level = max(level - 1, 0)
        ladder.append("C=recorded: one level down — recorded "
                      "compensating controls reduce the computed "
                      "severity")

    # critical is only reachable via registered_high + observed
    if level == 4 and not (business_impact == "registered_high"
                           and exposure == "observed"):
        level = 3
        ladder.append("'critical' requires B=registered_high and "
                      "X=observed; capped at 'high'")

    severity = reverse[level]
    return RiskAssessment(
        severity_label=severity,
        model_version=RISK_MODEL_VERSION,
        factors=factors,
        derivation=ladder)
