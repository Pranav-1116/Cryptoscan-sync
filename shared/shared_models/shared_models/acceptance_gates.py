"""Product acceptance gates (gap analysis §6) — the twelve gates that stand
before a supervised bank pilot.

Each gate's pass condition is a claim about evidence. The register files that
evidence; it never declares a gate passed without it. Two gates — ``RECOVERY``
(backup and restore are demonstrated) and ``COLLECTOR_QUALIFICATION``
(supported integrations have documented test evidence against real
environments) — are **external-only**: the acts happen outside this platform,
and this register only records the evidence someone files afterwards, exactly
like :mod:`shared_models.external_validation`.

    "The synthetic accuracy figures from the earlier Guide 185 review should
    remain labelled as synthetic results until real-estate qualification
    supports stronger claims."

So synthetic evidence may support an in-repo gate but is labelled synthetic
and never upgrades an external gate.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

GATES_SCHEMA = "cryptoscan.acceptance-gates/1"

EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
DISCOVERY_COVERAGE = "DISCOVERY_COVERAGE"
ASSET_IDENTITY = "ASSET_IDENTITY"
RELATIONSHIP_ACCURACY = "RELATIONSHIP_ACCURACY"
CRYPTO_TRUTH = "CRYPTO_TRUTH"
BOM_CONSISTENCY = "BOM_CONSISTENCY"
DIGITAL_TWIN = "DIGITAL_TWIN"
THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
PQC_PLANNING = "PQC_PLANNING"
TENANT_SECURITY = "TENANT_SECURITY"
RECOVERY = "RECOVERY"
COLLECTOR_QUALIFICATION = "COLLECTOR_QUALIFICATION"

GATE_CONDITIONS: dict[str, str] = {
    EVIDENCE_INTEGRITY: "tampering and invalid references are detected",
    DISCOVERY_COVERAGE: "every authorized target has an explicit collection outcome",
    ASSET_IDENTITY: "cross-collector duplicates are controlled",
    RELATIONSHIP_ACCURACY: "relationships are evidence-backed",
    CRYPTO_TRUTH: "capability is not reported as actual usage",
    BOM_CONSISTENCY: "cross-BOM references reconcile correctly",
    DIGITAL_TWIN: "historical state and impact are reproducible",
    THREAT_INTELLIGENCE: "findings explain evidence and uncertainty",
    PQC_PLANNING: "migration recommendations expose assumptions and blockers",
    TENANT_SECURITY: "cross-tenant access tests pass",
    RECOVERY: "backup and restore are demonstrated",
    COLLECTOR_QUALIFICATION: "supported integrations have documented test evidence",
}

#: gates whose passing acts happen outside this platform
EXTERNAL_GATES: frozenset[str] = frozenset({RECOVERY, COLLECTOR_QUALIFICATION})

PASSED, NOT_PASSED = "PASSED", "NOT_PASSED"
SYNTHETIC = "SYNTHETIC"


def file_gate_evidence(*, gate: str, evidence_ids: Sequence[str],
                       performed_by: str, performed_at: str,
                       result: str = PASSED,
                       synthetic: bool = False,
                       note: str | None = None) -> dict[str, Any]:
    """File evidence against one gate. Refuses claims with no evidence.

    ``performed_by`` names the party that produced the evidence. For external
    gates the platform cannot be that party, and synthetic evidence never
    passes an external gate — a synthetic drill is not a demonstrated restore.
    """
    name = str(gate or "").upper()
    if name not in GATE_CONDITIONS:
        raise ValueError(f"unknown gate {gate!r}; expected one of "
                         f"{', '.join(GATE_CONDITIONS)}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "gate evidence is mandatory: a pass condition without evidence is "
            "an opinion")
    who = str(performed_by or "").strip()
    if not who:
        raise ValueError("performed_by is mandatory: gate evidence names who "
                         "produced it")
    if name in EXTERNAL_GATES and who.lower() in {"cryptoscan", "crypto scan",
                                                  "the platform", "platform"}:
        raise ValueError(
            f"{name} is an external gate: its acts happen outside this "
            f"platform (a real restore drill, a real-environment "
            f"qualification) and the platform cannot be the performer")
    if name in EXTERNAL_GATES and synthetic:
        raise ValueError(
            "synthetic evidence never passes an external gate: a synthetic "
            "drill is not a demonstrated restore, and fixture results are "
            "labelled synthetic until real-estate qualification supports "
            "stronger claims")
    outcome = str(result or "").upper()
    if outcome not in {PASSED, NOT_PASSED}:
        raise ValueError(f"unknown result {result!r}; expected {PASSED} or "
                         f"{NOT_PASSED}")
    return {
        "schema": GATES_SCHEMA,
        "gate": name, "evidence_ids": ids, "performed_by": who,
        "performed_at": str(performed_at), "result": outcome,
        "synthetic": bool(synthetic),
        "note": str(note) if note else None,
    }


def gates_status(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Status per gate. A gate with no filed evidence is ``NOT_PASSED``.

    A failed filing keeps the gate ``NOT_PASSED`` with the failure visible;
    the newest filing decides; synthetic-only filings report a gate that is
    evidence-backed but still labelled synthetic.
    """
    records = [dict(r) for r in rows]
    gates: dict[str, Any] = {}
    for gate, condition in GATE_CONDITIONS.items():
        history = sorted((r for r in records if str(r.get("gate")) == gate),
                         key=lambda r: str(r.get("performed_at") or ""))
        if not history:
            gates[gate] = {
                "status": NOT_PASSED, "condition": condition,
                "latest": None, "history": [], "synthetic_only": False,
                "reason": ("no evidence filed: this gate is not passed — a "
                           "pass condition is a claim about evidence"),
            }
            continue
        latest = history[-1]
        synthetic_only = all(r.get("synthetic") for r in history)
        passed = (latest.get("result") == PASSED
                  and not (gate in EXTERNAL_GATES and synthetic_only))
        gates[gate] = {
            "status": PASSED if passed else NOT_PASSED,
            "condition": condition, "latest": latest, "history": history,
            "synthetic_only": synthetic_only,
            "reason": (
                f"evidence filed by {latest.get('performed_by')} on "
                f"{latest.get('performed_at')}"
                + (" (synthetic: labelled synthetic until real-estate "
                   "qualification supports stronger claims)"
                   if synthetic_only else "")
                + ("" if passed else f": latest result is "
                                     f"{latest.get('result')}")),
        }
    passed_count = sum(1 for g in gates.values() if g["status"] == PASSED)
    return {
        "schema": GATES_SCHEMA,
        "gates": gates,
        "counts": {PASSED: passed_count, NOT_PASSED: len(gates) - passed_count},
        "pilot_ready": passed_count == len(gates),
        "note": ("the gates stand before a supervised bank pilot: the "
                 "external gates are performed outside this platform and "
                 "filed here, and no gate passes without evidence"),
    }
