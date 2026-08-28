"""Vendor crypto risk score (0-100). Deterministic.

Classification goes through the shared algorithm registry (statuses for
any name — code names, TLS suites, protocol versions, JOSE) and the
shared quantum classifier (evidence-based PQC exposure). Self-reported
questionnaire answers are still used — but inventory evidence wins when
the two disagree.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from shared_models.algorithm_registry import (
    DEPRECATED,
    DISALLOWED,
    RESTRICTED,
    UNKNOWN,
    parse_algorithm,
)
from shared_models.quantum_classify import PQC_RESISTANT, SHOR_VULNERABLE, quantum_verdict, summarize_verdicts

SENSITIVE = {"PCI", "PCI-DSS", "PHI", "PII", "PAN", "CLASSIFIED"}

_STATUS_LADDER = (
    (DISALLOWED, 50, "Weak or deprecated crypto"),
    (DEPRECATED, 35, "Deprecated crypto"),
    (RESTRICTED, 25, "Restricted crypto"),
)


def _norm(value: str | None) -> str:
    return (value or "").upper().replace(" ", "")


def _classify_inventory(algos: list[str]) -> dict[str, Any]:
    """Worst-status ladder over the parsed inventory."""
    statuses: dict[str, int] = {}
    recognized = 0
    for algo in algos:
        info = parse_algorithm(algo)
        status = info.status if info.recognized else UNKNOWN
        statuses[status] = statuses.get(status, 0) + 1
        if info.recognized:
            recognized += 1
    crypto_risk, issue = 30, "No crypto disclosure"
    if algos:
        for status, risk, label in _STATUS_LADDER:
            if statuses.get(status):
                crypto_risk, issue = risk, label
                break
        else:
            if recognized:
                crypto_risk, issue = 5, "Strong crypto"
            else:
                crypto_risk, issue = 25, "Unclassified crypto"
    return {
        "crypto_risk": crypto_risk,
        "issue": issue,
        "by_status": dict(sorted(statuses.items())),
        "recognized": recognized,
    }


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

    classified = _classify_inventory(algos)
    crypto_risk, issue = classified["crypto_risk"], classified["issue"]

    status = (pqc_status or profile.get("pqc_status") or "none").lower()
    if status in {"ready", "yes", "deployed"}:
        pqc_risk = 0
    elif status in {"planned", "roadmap"}:
        pqc_risk = 10
    elif long_lived_data:
        pqc_risk = 30
    else:
        pqc_risk = 15

    # Evidence from the disclosed inventory, via the shared classifier.
    evidence = summarize_verdicts(algos)
    shor_sites = (evidence["counts"] or {}).get(SHOR_VULNERABLE, 0)
    pqc_sites = (evidence["counts"] or {}).get(PQC_RESISTANT, 0)
    pqc_algorithms = sorted(
        {row["algorithm"] for row in (quantum_verdict(algo) for algo in algos) if row["verdict"] == PQC_RESISTANT}
    )
    discrepancy = None
    if pqc_sites and not shor_sites:
        pqc_risk = 0  # deployed PQC evidence beats paperwork lag
    if shor_sites and status in {"ready", "yes", "deployed"}:
        discrepancy = "claims PQC readiness but disclosed inventory still contains Shor-vulnerable crypto"
        pqc_risk = max(pqc_risk, 20)

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
        "pqc_evidence": {
            "shor_vulnerable_sites": shor_sites,
            "shor_vulnerable_algorithms": evidence["shor_vulnerable_algorithms"],
            "pqc_algorithms": pqc_algorithms,
            "unknown_names": evidence["unknown_names"],
            "discrepancy": discrepancy,
            "inventory_algorithms": len(algos),
            "note": "computed from the disclosed inventory via the shared classifier; an empty inventory is no evidence, not safety",
        },
        "inventory_summary": {
            "algorithms": len(algos),
            "recognized": classified["recognized"],
            "by_status": classified["by_status"],
        },
    }
