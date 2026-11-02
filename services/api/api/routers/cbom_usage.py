"""CBOM usage proof: what the evidence observed, and what a CBOM may not claim.

Three read-only surfaces over :mod:`cbom.usage_evidence`:

* ``POST /cbom/usage`` — one asset's capability, per-layer observations, evidence
  ids and deterministically computed confidence; optionally the candidate
  algorithms a crypto-capable library supports (candidates, never ``USED``).
* ``POST /cbom/reconcile`` — every source's claim kept side by side, with
  conflicts stated instead of collapsed into one value.
* ``POST /cbom/tls-paths`` — one relationship per TLS hop, attributed to the
  endpoint that terminated it rather than to the application behind it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import require_roles

router = APIRouter(prefix="/cbom", tags=["cbom"])

#: Reading a usage profile is an analysis action: analysts, the CISO, auditors
#: (read-only reports) and supervisors may ask. It is not a dashboard read, and it
#: is not a write, so it takes a role rather than only a session.
CBOM_USAGE_READERS = ("superadmin", "ciso", "security_analyst", "auditor", "supervisor")


class CbomUsageRequest(BaseModel):
    asset: dict = Field(..., description=(
        "the asset under question: algorithm, parameters (key_size/mode/curve), purpose"))
    evidence: list[dict] = Field(default_factory=list, description=(
        "evidence events: class or layer, evidence_id, algorithm, purpose, location, "
        "observed_at. An observation with no evidence id is refused; an IMPORTED event "
        "can never be promoted to an observation"))
    component: str | None = Field(None, description=(
        "crypto-capable library to expand into candidate algorithms (capability only)"))
    algorithms: list[str] = Field(default_factory=list, description=(
        "algorithms the component supports, listed as candidates and never as usage"))


class CbomUsageResponse(BaseModel):
    profile: dict
    candidates: dict | None = None


class CbomReconcileRequest(BaseModel):
    claims: list[dict] = Field(..., description=(
        "one row per source: field, fact, source (kb/sbom/container/runtime/network/vendor) "
        "and evidence_id. Observing sources that disagree produce a conflict; nothing is "
        "collapsed"))


class CbomReconcileResponse(BaseModel):
    schema_: str = Field(alias="schema")
    rows: list[dict]
    conflicts: list[dict]
    resolved: list[dict]
    refused: list[dict]
    statement: str


class CbomTlsPathsRequest(BaseModel):
    hops: list[dict] = Field(..., description=(
        "TLS hops as observed: from, to, endpoint, observed_on, tls_version, cipher_suite, "
        "key_exchange, certificate_ref, evidence_id"))


class CbomHsmRequest(BaseModel):
    kind: str = Field(..., description=(
        "CAPABILITY, CONFIGURED_KEY or OPERATION — the three HSM/KMS answers, only the last "
        "of which is usage"))
    evidence_id: str | None = None
    operation: str | None = None


@router.post("/usage", response_model=CbomUsageResponse)
def cbom_usage(body: CbomUsageRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Capability, per-layer observation, evidence and confidence for one asset.

    The answer keeps the review's distinctions: ``CANDIDATE_ONLY`` means something
    *could* use this algorithm, ``OBSERVED`` means a layer watched it happen, and
    ``confidence`` is computed from the classes present — runtime and network
    together are ``VERY_HIGH`` because they are independent collection mechanisms.
    """
    from cbom import usage_evidence as ue

    try:
        profile = ue.usage_profile(body.asset, body.evidence)
    except ue.EvidenceRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    candidates = None
    if body.component:
        candidates = ue.capability_candidates(body.component, body.algorithms,
                                              evidence_id=f"component:{body.component}")
    return {"profile": profile, "candidates": candidates}


@router.post("/reconcile", response_model=CbomReconcileResponse)
def cbom_reconcile(body: CbomReconcileRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Every source's claim, the conflicts between observers, and a precedence note."""
    from cbom import usage_evidence as ue

    return ue.reconcile(body.claims)


@router.post("/tls-paths")
def cbom_tls_paths(body: CbomTlsPathsRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """One cryptographic relationship per hop (terminations are not applications)."""
    from cbom import usage_evidence as ue

    return ue.tls_paths(body.hops)


@router.post("/hsm-evidence")
def cbom_hsm_evidence(body: CbomHsmRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """HSM capability vs configured key vs recorded operation, kept apart."""
    from cbom import usage_evidence as ue

    try:
        return ue.hsm_evidence(body.kind, evidence_id=body.evidence_id,
                               operation=body.operation)
    except ue.EvidenceRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc))
