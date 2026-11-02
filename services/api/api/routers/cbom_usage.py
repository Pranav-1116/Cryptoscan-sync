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
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles

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


class CbomCollectRequest(BaseModel):
    probes: list[dict] = Field(default_factory=list, description=(
        "network-scanner probes: endpoint, status, crypto.{tls_version,cipher_suite}, "
        "certificates[], scan_run_id or evidence_id. A probe that negotiated nothing "
        "produces no evidence"))
    assets: list[dict] = Field(default_factory=list, description=(
        "stored crypto findings: algorithm, key_size, mode, purpose, file_path, line_number, "
        "evidence_ids[]. A finding with no evidence row is refused"))
    operations: list[dict] = Field(default_factory=list, description=(
        "recorded crypto operations: operation, algorithm, key_size/mode/curve, evidence_id, "
        "observed_at, process. A row missing any of those is a claim, not an observation"))
    scan_run_id: str | None = Field(None, description="scan run the probes belong to")
    purposes: dict = Field(default_factory=dict, description="algorithm -> purpose")


class CbomCollectResponse(BaseModel):
    network: dict
    static: dict
    runtime: dict
    profiles: dict


class CbomNetworkUsageResponse(BaseModel):
    profiles: dict
    certificates: list[dict]
    hops: dict
    source: str
    scan_runs: int


class CbomGraphRequest(BaseModel):
    profiles: list[dict] | None = Field(None, description=(
        "usage profiles (as returned by /cbom/usage or /cbom/usage/collect); one "
        "USES_CRYPTO edge per algorithm, classified by the strongest evidence class"))
    reconciled: dict | None = Field(None, description=(
        "output of /cbom/reconcile; each conflict becomes a CONFLICTS_WITH edge with both "
        "sides' evidence — no conflict is ever resolved into an edge"))
    paths: dict | None = Field(None, description=(
        "output of /cbom/tls-paths; endpoints negotiate algorithms and terminate with "
        "certificates, and a terminator's algorithms never become the application's"))
    system: str | None = None
    application: str | None = None
    component: str | None = None


class CbomGraphResponse(BaseModel):
    edges: dict
    applied: dict
    graph: dict


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


@router.post("/usage/collect", response_model=CbomCollectResponse)
def cbom_usage_collect(body: CbomCollectRequest,
                       user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Turn rows this platform already holds into CBOM evidence, then profile them.

    Network probes become ``NETWORK_OBSERVED``, stored findings with their
    evidence rows become ``STATIC_OBSERVED``, recorded operations become
    ``RUNTIME_OBSERVED`` — and every source's refusals are reported rather than
    dropped, because a row that cannot be attributed is an inventory entry, not
    an observation.
    """
    from cbom import usage_collectors as uc

    network = uc.network_events_from_probes(body.probes, scan_run_id=body.scan_run_id)
    static = uc.static_events_from_assets(body.assets)
    runtime = uc.runtime_events_from_operations(body.operations)
    profiles = uc.profiles(network["events"] + static["events"] + runtime["events"],
                           purposes=body.purposes)
    return {"network": network, "static": static, "runtime": runtime, "profiles": profiles}


@router.get("/usage/network", response_model=CbomNetworkUsageResponse)
def cbom_usage_network(db: Session = Depends(get_db_session),
                       user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """The network half of the usage profile, read from stored scan runs.

    This is the collector the network scanner already feeds: each run's probes
    become ``NETWORK_OBSERVED`` facts carrying the run they came from, plus the
    certificates served and one hop per observed endpoint. Nothing here claims
    anything about the application behind a terminator.
    """
    from cbom import usage_collectors as uc
    from db.models.network_scan_run import NetworkScanRun

    runs = db.execute(
        select(NetworkScanRun).order_by(NetworkScanRun.created_at.desc(),
                                        NetworkScanRun.id.desc()).limit(20)
    ).scalars().all()
    probes: list[dict] = []
    for run in runs:
        for probe in ((run.result or {}).get("probes") or []):
            if isinstance(probe, dict):
                probes.append({**probe, "scan_run_id": probe.get("scan_run_id") or run.id,
                               "observed_at": probe.get("observed_at")
                               or (run.created_at.isoformat() if run.created_at else None)})
    collected = uc.network_events_from_probes(probes)
    profiles = uc.profiles(collected["events"])
    return {"profiles": profiles, "certificates": collected["certificates"],
            "hops": {"schema": collected["schema"], "paths": collected["hops"],
                     "statement": collected["statement"]},
            "source": "live" if probes else "empty", "scan_runs": len(runs)}


@router.post("/usage/graph", response_model=CbomGraphResponse)
def cbom_usage_graph(body: CbomGraphRequest,
                     user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """CBOM relationships as graph edges, written with their evidence attached.

    Three families: ``USES_CRYPTO`` (classified by the strongest evidence class —
    an SBOM-only algorithm is ``DECLARED``), ``CONFLICTS_WITH`` (two sources
    disagreeing, both evidence ids kept, never resolved into a chosen value) and
    ``NEGOTIATES``/``TERMINATES`` (a terminator's algorithms belong to the
    terminator). An edge without evidence is refused rather than drawn.
    """
    from cbom import usage_graph as ug
    from graph_engine.core.engine import GraphEngine

    try:
        edges = ug.build_graph(body.profiles, reconciled=body.reconciled, paths=body.paths,
                               system=body.system, application=body.application,
                               component=body.component)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    engine = GraphEngine()
    applied = ug.apply_graph(engine, edges["edges"])
    return {"edges": edges, "applied": applied, "graph": engine.to_vis()}


@router.post("/hsm-evidence")
def cbom_hsm_evidence(body: CbomHsmRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """HSM capability vs configured key vs recorded operation, kept apart."""
    from cbom import usage_evidence as ue

    try:
        return ue.hsm_evidence(body.kind, evidence_id=body.evidence_id,
                               operation=body.operation)
    except ue.EvidenceRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc))
