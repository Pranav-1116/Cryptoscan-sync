"""Vendor crypto risk score (0-100). Deterministic."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

WEAK = ("DES", "MD5", "RC4", "TLS1.0", "TLS 1.0", "TLS1.1", "TLS 1.1", "SHA-1", "SHA1", "RSA-1024")
MODERATE = ("RSA-2048", "RSA2048", "AES-128", "AES128", "TLS1.2", "TLS 1.2")
STRONG = ("AES-256", "AES256", "TLS1.3", "TLS 1.3", "ML-KEM", "ML-DSA", "CHACHA20")
SENSITIVE = {"PCI", "PCI-DSS", "PHI", "PII", "PAN", "CLASSIFIED"}


def _norm(value: str | None) -> str:
    return (value or "").upper().replace(" ", "")


def score_vendor(
    *,
    inventory: Iterable[Mapping[str, Any]] = (),
    classifications: Iterable[str] = (),
    pqc_status: str | None = None,
    cbom_provided: bool | None = None,
    refuses_disclosure: bool = False,
    long_lived_data: bool = False,
    profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    profile = dict(profile or {})
    items = list(inventory) or list(profile.get("inventory") or [])
    algos = [_norm(str(item.get("algorithm") or "")) for item in items]
    if profile.get("data_in_transit"):
        algos.append(_norm(str(profile.get("data_in_transit"))))
    if profile.get("data_at_rest"):
        algos.append(_norm(str(profile.get("data_at_rest"))))
    if any(any(token.replace(" ", "") in algo for token in WEAK) for algo in algos):
        crypto_risk = 50
        issue = "Weak or deprecated crypto"
    elif any(any(token.replace(" ", "") in algo for token in STRONG) for algo in algos) and not any(
        any(token.replace(" ", "") in algo for token in MODERATE) for algo in algos
    ):
        crypto_risk = 5
        issue = "Strong crypto"
    elif any(any(token.replace(" ", "") in algo for token in MODERATE) for algo in algos):
        crypto_risk = 25
        issue = "Moderate crypto"
    elif algos:
        crypto_risk = 25
        issue = "Unclassified crypto"
    else:
        crypto_risk = 30
        issue = "No crypto disclosure"

    status = (pqc_status or profile.get("pqc_status") or "none").lower()
    if status in {"ready", "yes", "deployed"}:
        pqc_risk = 0
    elif status in {"planned", "roadmap"}:
        pqc_risk = 10
    elif long_lived_data:
        pqc_risk = 30
    else:
        pqc_risk = 15

    classes = {str(item).upper() for item in (classifications or profile.get("data_classifications") or [])}
    multiplier = 1.5 if classes & SENSITIVE else 1.0
    provided = cbom_provided if cbom_provided is not None else bool(profile.get("cbom_provided"))
    transparency = -10 if provided else 20 if refuses_disclosure else 0
    score = int(round((crypto_risk + pqc_risk) * multiplier + transparency))
    score = max(0, min(100, score))
    if score > 70:
        category, action = "HIGH", "Review vendor contract. Request upgrade."
    elif score > 40:
        category, action = "MEDIUM", "Monitor. Plan contingency."
    else:
        category, action = "LOW", "No action needed."
    return {
        "vendor_crypto_risk_score": score,
        "score": score,
        "vendor_risk_category": category,
        "category": category,
        "action": action,
        "issue": issue,
        "factors": {
            "crypto_risk": crypto_risk,
            "pqc_risk": pqc_risk,
            "data_risk_multiplier": multiplier,
            "transparency": transparency,
        },
        "pqc_status": status,
    }
