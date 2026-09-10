"""§20 Crypto agility detection — can the system easily change its crypto?

Score 0–100 from structural signals (never a guess):
  hard-coded algorithm/key size/curve/suite   → severe penalty (15-range)
  configurable provider                       → strong score (75-range)
  algorithm abstraction + runtime selection   → top score (95-range)
"""

from __future__ import annotations

from typing import Any, Iterable

#: structural signals with deterministic contributions
SIGNALS: list[dict[str, Any]] = [
    # baseline 50; the §20 example profiles calibrate to 15 / 75 / 95
    {"signal": "hardcoded_algorithm", "score": -10, "impact": "algorithm cannot change without code change"},
    {"signal": "hardcoded_key_size", "score": -10, "impact": "key size cannot change without code change"},
    {"signal": "hardcoded_curve", "score": -10, "impact": "curve cannot change without code change"},
    {"signal": "hardcoded_cipher_suite", "score": -10, "impact": "cipher suite cannot change without code change"},
    {"signal": "hardcoded_certificate", "score": -15, "impact": "certificate pinned in code"},
    {"signal": "hardcoded_provider", "score": -10, "impact": "provider pinned in code"},
    {"signal": "hardcoded_kem", "score": -15, "impact": "KEM hardcoded"},
    {"signal": "configurable_algorithm", "score": +5, "impact": "algorithm configurable"},
    {"signal": "configurable_key_size", "score": +5, "impact": "key size configurable"},
    {"signal": "configurable_curve", "score": +10, "impact": "curve configurable"},
    {"signal": "configurable_provider", "score": +5, "impact": "crypto provider configurable"},
    {"signal": "configurable_tls_config", "score": +5, "impact": "TLS configuration configurable"},
    {"signal": "algorithm_abstraction", "score": +15, "impact": "algorithm abstraction layer present"},
    {"signal": "runtime_selection", "score": +15, "impact": "algorithm selected at runtime"},
    {"signal": "single_provider", "score": -5, "impact": "only one crypto provider"},
    {"signal": "multiple_providers", "score": +5, "impact": "multiple crypto providers"},
]

#: example profiles from §20
PROFILES = {
    "hardcoded": ["hardcoded_algorithm", "hardcoded_key_size",
                  "hardcoded_cipher_suite", "single_provider"],
    "configurable": ["configurable_algorithm", "configurable_key_size",
                     "configurable_provider", "configurable_tls_config",
                     "multiple_providers"],
    "abstraction": ["algorithm_abstraction", "runtime_selection",
                    "configurable_algorithm", "configurable_provider",
                    "configurable_key_size"],
}


class CryptoAgilityEngine:
    """§20 deterministic agility scoring."""

    def score(self, signals: Iterable[str]) -> dict[str, Any]:
        present = set(signals)
        total = 50.0  # neutral baseline
        applied: list[dict[str, Any]] = []
        for signal in SIGNALS:
            if signal["signal"] in present:
                total += signal["score"]
                applied.append(signal)
        score = max(0, min(100, round(total)))
        return {
            "score": score,
            "signals": [s["signal"] for s in applied],
            "impacts": [s["impact"] for s in applied],
            "band": ("HIGH" if score >= 80 else "MEDIUM" if score >= 50
                     else "LOW"),
        }

    def profile(self, name: str) -> dict[str, Any]:
        """The §20 examples: hard-coded RSA → 15, configurable → 75,
        abstraction+runtime → 95."""
        signals = PROFILES.get(name)
        if signals is None:
            raise KeyError(name)
        return self.score(signals)

    def score_asset(self, *, asset_id: str,
                    signals: Iterable[str]) -> dict[str, Any]:
        result = self.score(signals)
        result["asset_id"] = asset_id
        return result
