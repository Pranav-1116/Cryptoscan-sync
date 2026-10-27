"""Hardware risk engine (§18).

Risk = hardware criticality + crypto dependency + age + firmware state +
PQC capability + business criticality + network exposure + replacement
difficulty.

Example: critical banking HSM + legacy firmware + no PQC support + high
dependency count → CRITICAL HARDWARE PQC RISK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

_CRITICALITY_WEIGHTS = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_EXPOSURE_WEIGHTS = {"internet": 3, "dmz": 2, "internal": 1, "isolated": 0}
_FIRMWARE_WEIGHTS = {"legacy": 2, "outdated": 1, "current": 0, "unknown": 1}


@dataclass
class HardwareRiskScore:
    asset_id: str
    score: int
    level: str
    components: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "score": self.score,
                "level": self.level, "components": self.components}


class HardwareRiskEngine:
    def assess(
        self,
        *,
        asset_id: str,
        hardware_criticality: str = "medium",   # critical | high | medium | low
        crypto_dependency_count: int = 0,
        age_years: float = 0.0,
        firmware_state: str = "unknown",        # legacy | outdated | current | unknown
        pqc_capability: str = "UNKNOWN",        # from evidence-backed DB
        business_criticality: str = "medium",
        network_exposure: str = "internal",     # internet | dmz | internal | isolated
        replacement_difficulty: str = "medium", # high | medium | low
    ) -> HardwareRiskScore:
        score = 0
        score += _CRITICALITY_WEIGHTS.get(hardware_criticality, 1)
        score += _CRITICALITY_WEIGHTS.get(business_criticality, 1)
        score += min(crypto_dependency_count, 5)
        score += _FIRMWARE_WEIGHTS.get(firmware_state, 1)
        score += _EXPOSURE_WEIGHTS.get(network_exposure, 1)
        score += 2 if pqc_capability in ("UNKNOWN", "NOT_SUPPORTED") else (
            1 if pqc_capability == "ROADMAP_DECLARED" else 0)
        score += 2 if age_years >= 8 else (1 if age_years >= 4 else 0)
        score += {"high": 2, "medium": 1, "low": 0}.get(replacement_difficulty, 1)

        level = "CRITICAL" if score >= 12 else ("HIGH" if score >= 9
                                                else ("MEDIUM" if score >= 6 else "LOW"))
        return HardwareRiskScore(
            asset_id=asset_id, score=score, level=level,
            components={
                "hardware_criticality": hardware_criticality,
                "crypto_dependency_count": crypto_dependency_count,
                "age_years": age_years,
                "firmware_state": firmware_state,
                "pqc_capability": pqc_capability,
                "business_criticality": business_criticality,
                "network_exposure": network_exposure,
                "replacement_difficulty": replacement_difficulty,
            },
        )
