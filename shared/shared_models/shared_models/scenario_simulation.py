"""Scenario simulation against a selected versioned snapshot (roadmap item 8).

Twelve scenarios — migration to ML-DSA, hybrid key establishment, HSM failure,
KMS outage, certificate expiry, TLS downgrade, library vulnerability, vendor
retirement, CA compromise, trust-path modification, provider replacement,
segmentation change — simulated over **recorded evidence**, with three rules the
output enforces at the point of use:

* the run names the snapshot it simulated (``snapshot_id`` and version are
  mandatory inputs — there is no "current state" in a simulator);
* every affected chain is labelled by its provenance, so a **proven** dependency
  is never presented alongside an **assumed** one as if they were equal;
* the whole output is a ``SIMULATION`` and says so: a hypothetical result is
  never shown as a real production change, and the approval and rollback columns
  are what *would* be required, not what has happened.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from shared_models.relationship_provenance import (
    INFERRED, PROVEN, UNKNOWN, impact_closure,
)

SIMULATION_SCHEMA = "cryptoscan.scenario-simulation/1"
SIMULATION_KIND = "SIMULATION"

#: the twelve scenarios the roadmap names
SCENARIOS: dict[str, str] = {
    "RSA_2048_TO_ML_DSA": "migrate RSA-2048 signing to ML-DSA",
    "HYBRID_PQ_KEY_ESTABLISHMENT": "roll out hybrid post-quantum key establishment",
    "HSM_FAILURE": "an HSM fails or becomes unavailable",
    "KMS_OUTAGE": "a KMS becomes unavailable",
    "CERTIFICATE_EXPIRY": "a certificate expires without renewal",
    "TLS_DOWNGRADE": "TLS negotiation downgrades to a weaker suite",
    "LIBRARY_VULNERABILITY": "a crypto library ships a critical vulnerability",
    "VENDOR_RETIREMENT": "a vendor retires the product or support",
    "CA_COMPROMISE": "a certificate authority is compromised",
    "TRUST_PATH_MODIFICATION": "the trust path is modified outside change control",
    "PROVIDER_REPLACEMENT": "a crypto provider is replaced across the estate",
    "SEGMENTATION_CHANGE": "network segmentation changes reachability",
}

#: scenarios whose output is a migration plan rather than an incident response
MIGRATION_KINDS = {"RSA_2048_TO_ML_DSA", "HYBRID_PQ_KEY_ESTABLISHMENT",
                   "PROVIDER_REPLACEMENT"}

_APPROVALS_BY_KIND = {
    "change": ["change advisory board approval",
               "security architect sign-off on the target algorithms",
               "rollback owner named before the window"],
    "incident": ["incident commander assignment",
                 "communications plan for affected service owners"],
    "trust": ["certificate authority / PKI owner approval",
              "security architect sign-off on the new trust path"],
}
_ROLLBACK_BY_KIND = {
    "change": ["pre-change snapshot of every touched subject, restore tested first",
               "dual-run or dual-stack window where the platform supports one",
               "revert procedure documented and rehearsed per subject"],
    "incident": ["failover to the secondary provider or HSM",
                 "degraded-mode plan for services that cannot fail over"],
    "trust": ["re-pin the previous trust path from the snapshot",
              "revoke or reissue certificates minted under the modified path"],
}


def _scenario_kind(name: str) -> str:
    if name in MIGRATION_KINDS:
        return "change"
    if name in {"CA_COMPROMISE", "TRUST_PATH_MODIFICATION"}:
        return "trust"
    return "incident"


def run_scenario(*, scenario: str,
                 snapshot: Mapping[str, Any],
                 focal_asset: str,
                 edges: Sequence[Mapping[str, Any]] = (),
                 evidence_by_id: Mapping[str, Mapping[str, Any]] | None = None,
                 assessments: Sequence[Mapping[str, Any]] = (),
                 parameters: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Simulate one scenario over one snapshot. Refuses to run without both.

    ``assessments`` are :func:`shared_models.pqc_decision.assess_subject` outputs
    for the subjects of interest; their blockers, compatibility rows and costs are
    folded into the result, so a simulated migration carries the same evidence a
    real plan would demand.
    """
    name = str(scenario or "").upper()
    if name not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; expected one of "
                         f"{', '.join(SCENARIOS)}")
    snapshot_id = str((snapshot or {}).get("snapshot_id") or "").strip()
    version = (snapshot or {}).get("version")
    captured_at = str((snapshot or {}).get("captured_at") or "").strip()
    if not snapshot_id or version is None or not captured_at:
        raise ValueError(
            "a scenario runs against a selected versioned snapshot: snapshot_id, "
            "version and captured_at are all required — there is no 'current "
            "state' in a simulator")

    closure = impact_closure(edges, focal_asset, evidence_by_id=evidence_by_id)
    proven = [row for row in closure["affected"]
              if row["hops"] and row["chain_provenance"] == PROVEN]
    assumed = [row for row in closure["affected"]
               if row["hops"] and row["chain_provenance"] in {INFERRED, UNKNOWN}]

    affected_names = {row["asset"] for row in closure["affected"]}
    relevant = [dict(a) for a in assessments
                if str(a.get("subject")) in affected_names]
    blockers = [{"subject": a["subject"], **b}
                for a in relevant for b in (a.get("blockers") or [])]
    compat_failures = [
        {"subject": a["subject"], "dependency": c["dependency"],
         "state": c["state"], "reason": c["reason"]}
        for a in relevant for c in (a.get("compatibility") or [])
        if c.get("state") in {"INCOMPATIBLE", "NOT_ASSESSED"}]
    cost_units = sum((a.get("cost") or {}).get("total_units", 0) for a in relevant)

    kind = _scenario_kind(name)
    result: dict[str, Any] = {
        "schema": SIMULATION_SCHEMA,
        "result_kind": SIMULATION_KIND,
        "hypothetical": True,
        "scenario": name,
        "description": SCENARIOS[name],
        "parameters": dict(parameters or {}),
        "snapshot": {"snapshot_id": snapshot_id, "version": version,
                     "captured_at": captured_at},
        "focal_asset": focal_asset,
        "affected": closure["affected"],
        "proven_dependencies": [
            {"asset": row["asset"], "chain": row["chain"]} for row in proven],
        "assumed_dependencies": [
            {"asset": row["asset"], "chain": row["chain"],
             "why_assumed": row["chain_provenance"]} for row in assumed],
        "blockers": blockers,
        "compatibility_failures": compat_failures,
        "cost": {"assessment_units": cost_units,
                 "note": ("units from the folded-in assessments under the "
                          "published cost rules — re-derivable, not estimated")},
        "approvals_required": _APPROVALS_BY_KIND[kind],
        "rollback_plan": _ROLLBACK_BY_KIND[kind],
        "note": ("this is a simulation over snapshot "
                 f"{snapshot_id} v{version}: every line is hypothetical and must "
                 "never be shown as a real production change; proven dependencies "
                 "and assumed dependencies are listed separately and are not the "
                 "same claim"),
    }
    return result


def scenario_catalog() -> dict[str, Any]:
    """The twelve scenarios and the rules a run enforces — for the UI and audits."""
    return {
        "schema": SIMULATION_SCHEMA,
        "scenarios": [{"name": name, "description": SCENARIOS[name],
                       "kind": _scenario_kind(name)}
                      for name in SCENARIOS],
        "requirements": ["a selected versioned snapshot (id, version, captured_at)",
                         "a focal asset",
                         "evidence-backed edges where dependency claims matter"],
        "note": ("every run is hypothetical output over recorded evidence: "
                 "proven and assumed dependencies are kept apart"),
    }
